#!/usr/bin/env python3
"""Conservative CTU-13 Argus -> Zeek HTTP transaction alignment (review only).

- HTTP transactions are first linked to Zeek conn.log by UID, from the same Zeek run.
- Argus flow is linked by the SAME directed 5-tuple + connection-start time (±2 s).
- An Argus flow cannot be claimed as independent direct match by multiple connections.
- Overlapping long-flow reuse is only a lower-confidence *association*.
- Argus naive timestamps are interpreted as Europe/Prague, a hypothesis previously
  validated only on the 53 directly matched Neris HTTP-C2 flows.
- Background is NOT treated as benign; no TP/FP/Precision/Recall/FPR computed.
- Does not modify the original detection alert matrix or dataset.
"""
from __future__ import annotations

import argparse
import bisect
import csv
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

REQUIRED_MATRIX = {
    'transaction_id', 'zeek_uid', 'src_ip', 'src_port', 'dst_ip',
    'dst_port', 'proto', 't1571', 't1071_001', 't1105',
}
REQUIRED_ARGUS = {'StartTime', 'Dur', 'Proto', 'SrcAddr', 'Sport', 'DstAddr', 'Dport', 'Label'}
OUTPUT_FIELDS = [
    'transaction_id', 'zeek_uid', 'http_ts_utc',
    'src_ip', 'src_port', 'dst_ip', 'dst_port', 'proto',
    'http_host', 'uri_path', 't1571', 't1071_001', 't1105',
    'zeek_conn_start_utc', 'zeek_conn_end_utc',
    'match_status', 'argus_candidate_count', 'argus_row_number',
    'argus_start_raw', 'argus_start_utc', 'argus_end_utc',
    'argus_start_minus_zeek_s', 'argus_label_for_review',
    'provisional_label_policy', 'independent_direct_flow_match',
    'evaluation_gate', 'notes'
]


def load_csv(path: Path):
    with path.open(newline='', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        return set(reader.fieldnames or []), list(reader)


def write_csv(path, fields, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        w.writeheader()
        w.writerows(rows)


def parse_port(value):
    s = str(value).strip()
    if not s:
        raise ValueError('Empty port')
    return int(s, 10)


def conn_key(row):
    return (str(row['id.orig_h']), parse_port(row['id.orig_p']),
            str(row['id.resp_h']), parse_port(row['id.resp_p']),
            str(row['proto']).strip().lower())


def matrix_key(row):
    return (str(row['src_ip']), parse_port(row['src_port']),
            str(row['dst_ip']), parse_port(row['dst_port']),
            str(row['proto']).strip().lower())


def argus_key(row):
    return (str(row['SrcAddr']).strip(), parse_port(row['Sport']),
            str(row['DstAddr']).strip(), parse_port(row['Dport']),
            str(row['Proto']).strip().lower())


def epoch(dt):
    return dt.timestamp()


def display_utc(timestamp):
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(timespec='microseconds')


def parse_prague(raw):
    text = str(raw).strip()
    try:
        dt = datetime.strptime(text, '%Y/%m/%d %H:%M:%S.%f')
    except ValueError:
        dt = datetime.strptime(text, '%Y/%m/%d %H:%M:%S')
    return epoch(dt.replace(tzinfo=ZoneInfo('Europe/Prague')).astimezone(timezone.utc))


def load_zeek_connections(path: Path, uids):
    found = {}
    with path.open(encoding='utf-8') as f:
        for line_no, line in enumerate(f, 1):
            if not line.strip() or line.startswith('#'):
                continue
            row = json.loads(line)
            uid = str(row.get('uid', ''))
            if uid not in uids:
                continue
            if uid in found:
                raise ValueError(f'Duplicate conn.log uid: {uid}')
            start = float(row['ts'])
            duration = float(row.get('duration') or 0.0)
            if duration < 0:
                raise ValueError(f'Negative Zeek duration, uid={uid}')
            found[uid] = {
                'key': conn_key(row), 'start': start,
                'end': start + duration,
            }
    missing = sorted(uids - set(found))
    if missing:
        raise ValueError(f'{len(missing)} matrix UID(s) missing in conn.log. First: {missing[:3]}')
    return found


def load_argus(path, interesting_keys):
    flows = []
    malformed_relevant = []
    relevant_endpoints = {(k[0], k[2], k[4]) for k in interesting_keys}
    with path.open(newline='', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        absent = REQUIRED_ARGUS - set(reader.fieldnames or [])
        if absent:
            raise ValueError(f'Missing Argus columns: {sorted(absent)}; observed={reader.fieldnames}')
        for row_no, row in enumerate(reader, 2):
            # A malformed port in an unrelated record can be safely skipped;
            # relevant malformed rows should be investigated separately.
            src, dst = str(row.get('SrcAddr', '')).strip(), str(row.get('DstAddr', '')).strip()
            proto = str(row.get('Proto', '')).strip().lower()
            if (src, dst, proto) not in relevant_endpoints:
                continue
            try:
                key = argus_key(row)
                if key not in interesting_keys:
                    continue
                start = parse_prague(row['StartTime'])
                dur = float(row['Dur'])
                if dur < 0:
                    raise ValueError('negative duration')
                flows.append({
                    'id': row_no, 'key': key,
                    'start': start, 'end': start + dur,
                    'start_raw': str(row['StartTime']), 'label': str(row['Label'])
                })
            except (ValueError, OverflowError) as ex:
                malformed_relevant.append(f'row {row_no}: {ex}')
    if malformed_relevant:
        raise ValueError('Relevant Argus rows malformed: ' + '; '.join(malformed_relevant[:5]))
    bykey = defaultdict(list)
    for flow in flows:
        bykey[flow['key']].append(flow)
    starts = {}
    for key, group in bykey.items():
        group.sort(key=lambda r: (r['start'], r['id']))
        starts[key] = [r['start'] for r in group]
    return flows, bykey, starts


def policy_candidate(label):
    if label.startswith('flow=From-Botnet-'):
        return 'dataset_positive_candidate'
    if label.startswith('flow=From-Normal-'):
        return 'dataset_negative_candidate'
    return 'unlabeled_or_requires_policy_review'


def classify_connections(conns, bykey, starts, window_s):
    by_uid = {}
    claims = defaultdict(list)
    for uid, c in conns.items():
        group = bykey.get(c['key'], ())
        stamps = starts.get(c['key'], ())
        lo = bisect.bisect_left(stamps, c['start'] - window_s)
        hi = bisect.bisect_right(stamps, c['start'] + window_s)
        hits = list(group[lo:hi])
        by_uid[uid] = {'start_hits': hits}
        if len(hits) == 1:
            claims[hits[0]['id']].append(uid)
    for uid, c in conns.items():
        item = by_uid[uid]
        direct = item['start_hits']
        if len(direct) > 1:
            item.update(status='ambiguous_start', chosen=None, candidates=len(direct),
                        note='Multiple Argus flows with same directed 5-tuple and nearby start')
        elif len(direct) == 1 and len(claims[direct[0]['id']]) > 1:
            item.update(status='ambiguous_multi_claim', chosen=None, candidates=len(claims[direct[0]['id']]),
                        note='Several Zeek connections claim same Argus start-time match')
        elif len(direct) == 1:
            item.update(status='direct_unique_start', chosen=direct[0], candidates=1,
                        note='Exact directed 5-tuple + start within window; Prague timezone assumption')
        else:
            # No close start: check if long Argus interval overlaps this Zeek connection.
            # This is lower confidence and is never an independent direct match.
            overlaps = [a for a in bykey.get(c['key'], ())
                        if a['start'] <= c['end'] and a['end'] >= c['start']]
            if len(overlaps) == 1:
                item.update(status='overlap_association_only', chosen=overlaps[0], candidates=1,
                            note='Same directed 5-tuple and temporal overlap; NOT independent 1:1 match')
            elif len(overlaps) > 1:
                item.update(status='ambiguous_overlap', chosen=None, candidates=len(overlaps),
                            note='Several Argus flows overlap; leave unlabeled')
            else:
                item.update(status='unmatched', chosen=None, candidates=0,
                            note='No exact directed 5-tuple + near start or overlap')
    return by_uid


def align(matrix_rows, conns, aligned):
    out = []
    for row in matrix_rows:
        uid = str(row['zeek_uid'])
        conn = conns[uid]
        if matrix_key(row) != conn['key']:
            raise ValueError(f'Matrix 5-tuple differs from Zeek conn.log for uid {uid}')
        m = aligned[uid]
        a = m['chosen']
        status = m['status']
        direct = status == 'direct_unique_start'
        label = a['label'] if a else ''
        policy = policy_candidate(label) if a else 'no_label'
        gate = ('provisional_direct_needs_label_policy_and_negative_coverage'
                if direct else 'exclude_from_strict_evaluation_pending_review')
        out.append({
            **row,
            'zeek_conn_start_utc': display_utc(conn['start']),
            'zeek_conn_end_utc': display_utc(conn['end']),
            'match_status': status,
            'argus_candidate_count': m['candidates'],
            'argus_row_number': a['id'] if a else '',
            'argus_start_raw': a['start_raw'] if a else '',
            'argus_start_utc': display_utc(a['start']) if a else '',
            'argus_end_utc': display_utc(a['end']) if a else '',
            'argus_start_minus_zeek_s': round(a['start'] - conn['start'], 6) if a else '',
            'argus_label_for_review': label,
            'provisional_label_policy': policy,
            'independent_direct_flow_match': 'yes' if direct else 'no',
            'evaluation_gate': gate,
            'notes': m['note'],
        })
    return out


def analyze(rows, aligned_conn, argus_count):
    status_tx = Counter(r['match_status'] for r in rows)
    status_conn = Counter(item['status'] for item in aligned_conn.values())
    policy_tx = Counter(r['provisional_label_policy'] for r in rows)
    per_rule = {}
    for rule in ('t1571', 't1071_001', 't1105'):
        hits = [r for r in rows if str(r[rule]) == '1']
        per_rule[rule] = {'alerted_transactions': len(hits),
                          'direct_start_matches': sum(r['match_status']=='direct_unique_start' for r in hits),
                          'overlap_associations': sum(r['match_status']=='overlap_association_only' for r in hits),
                          'unmatched_or_ambiguous': sum(r['match_status'] not in ('direct_unique_start', 'overlap_association_only') for r in hits)}
    http_c2 = [r for r in rows if r['dst_ip']=='31.192.109.167' and str(r['dst_port'])=='80' and r.get('uri_path','').startswith('/snapbn/')]
    return {
        'timezone_hypothesis': 'Argus StartTime interpreted as Europe/Prague, converted to UTC',
        'time_window_seconds': 2.0,
        'time_reference': 'Zeek conn.log connection start (NOT HTTP request timestamp)',
        'matching_unit': 'Zeek connection, then label ASSOCIATED with HTTP transactions',
        'argus_same_direction_candidate_rows_loaded': argus_count,
        'http_transactions': len(rows), 'unique_zeek_connection_uids': len(aligned_conn),
        'alignment_status_transactions': dict(status_tx),
        'alignment_status_unique_zeek_connections': dict(status_conn),
        'provisional_label_policy_transactions': dict(policy_tx),
        'per_rule': per_rule,
        'http_c2_snapbn_sanity_check': {
            'http_transactions': len(http_c2),
            'direct_unique_start': sum(r['match_status']=='direct_unique_start' for r in http_c2),
            'overlap_association_only': sum(r['match_status']=='overlap_association_only' for r in http_c2),
            'other': sum(r['match_status'] not in ('direct_unique_start','overlap_association_only') for r in http_c2),
            'week1_reference': '54 Zeek HTTP connections, 53 direct + 1 overlap (same PCAP/logs expected)'
        },
        'evaluation_status': 'NOT SCORED - no TP/FP/TN/FN or Precision/Recall/F1/FPR',
        'cautions': [
            'CTU-13 Background/To-Background is not a confirmed normal label.',
            'Full-payload PCAP does not necessarily include confirmed-normal HTTP traffic.',
            'Overlap association is lower confidence and NOT a second direct Argus flow match.',
            'One Zeek connection may contain multiple HTTP transactions; labels can repeat across transactions.',
            'Near-start time window and Prague timezone hypothesis need validation beyond HTTP-C2 endpoint.',
        ]
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repo', type=Path, default=Path.cwd())
    p.add_argument('--matrix', type=Path, default=Path('reports/week2/quy/generated/http_transaction_alert_matrix.csv'))
    p.add_argument('--argus', type=Path, default=Path('reports/week1/generated/neris_labeled_flows.csv'))
    p.add_argument('--conn', type=Path, default=Path('data/processed/scenario-01-neris/zeek/conn.log'))
    p.add_argument('--window-seconds', type=float, default=2.0)
    args = p.parse_args()
    if args.window_seconds <= 0:
        p.error('--window-seconds must be positive')
    repo = args.repo.expanduser().resolve()
    def here(pth):
        return pth if pth.is_absolute() else repo / pth
    matrix_path, argus_path, conn_path = map(here, (args.matrix, args.argus, args.conn))
    for path in (matrix_path, argus_path, conn_path):
        if not path.is_file():
            p.error(f'Required input not found: {path}')
    cols, matrix = load_csv(matrix_path)
    absent = REQUIRED_MATRIX - cols
    if absent:
        p.error(f'Matrix missing required columns: {sorted(absent)}')
    ids = [r['transaction_id'] for r in matrix]
    if len(ids) != len(set(ids)):
        p.error('Duplicate transaction IDs in normalized matrix')
    conn_uids = {r['zeek_uid'] for r in matrix}
    connections = load_zeek_connections(conn_path, conn_uids)
    interesting_keys = {c['key'] for c in connections.values()}
    argus, bykey, starts = load_argus(argus_path, interesting_keys)
    aligned_conn = classify_connections(connections, bykey, starts, args.window_seconds)
    rows = align(matrix, connections, aligned_conn)
    outdir = repo / 'reports/week2/quy/generated'
    output = outdir / 'http_argus_alignment_review.csv'
    write_csv(output, OUTPUT_FIELDS, rows)
    summary = analyze(rows, aligned_conn, len(argus))
    summary['time_window_seconds'] = args.window_seconds
    output_json = outdir / 'http_argus_alignment_summary.json'
    with output_json.open('w', encoding='utf-8') as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print(f'HTTP transactions: {len(rows)}; distinct Zeek connection UIDs: {len(connections)}')
    print(f'Relevant directed Argus flows: {len(argus)}')
    print('Zeek CONNECTION alignment status:', dict(Counter(x['status'] for x in aligned_conn.values())))
    print('Transaction provisional label policy:', dict(Counter(r['provisional_label_policy'] for r in rows)))
    print('HTTP-C2 sanity check:', summary['http_c2_snapbn_sanity_check'])
    print('Per-rule review:', summary['per_rule'])
    print(f'Outputs: {output.relative_to(repo)}; {output_json.relative_to(repo)}')
    print('NOT evaluation metrics. Review with Lam before computing TP/FP/TN/FN.')


if __name__ == '__main__':
    main()
