#!/usr/bin/env python3
"""NT140 Week 2: normalize three exploratory HTTP rules to one HTTP transaction per row.

Important:
- Reads Zeek JSON logs from ONE run and exact outputs of existing 3 detectors.
- This is an ALERT JOIN, not CTU-13 ground-truth alignment or a metrics calculator.
- Never use only sample_zeek_uids from grouped CSVs (they are truncated).
- HTTP transaction is identified by its http.log row number; UID can be reused
  across transactions in persistent connections.
- The MZ ledger is manual evidence with a specific UID/endpoint/URI/PCAP frame.
"""
from __future__ import annotations
import argparse
import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

RULES = {
    "t1571": "nonstandard_http_port_alerts.csv",
    "t1071_001": "web_behavior_alerts.csv",
    "t1105": "executable_ingress_events.csv",
}
WEB_STANDARD_PORTS = {80, 443, 8080}
COLUMNS = [
    "transaction_id", "http_log_line", "http_ts_utc", "zeek_uid",
    "src_ip", "src_port", "dst_ip", "dst_port", "proto", "http_host",
    "uri_path", "http_method", "http_status", "response_body_len",
    "conn_state", "http_response_fuids", "t1571", "t1071_001", "t1105",
    "triggered_rules", "mz_packet_verified", "mz_evidence_frame",
    "mz_evidence_tcp_stream", "mz_evidence_note", "ground_truth_label",
    "alignment_status", "alignment_evidence", "evaluation_status",
]
LONG_COLUMNS = ["transaction_id", "zeek_uid", "http_ts_utc", "rule", "dst_ip", "dst_port", "http_host", "uri_path"]


def read_json_lines(path: Path):
    with path.open(encoding="utf-8") as stream:
        for ln, line in enumerate(stream, 1):
            if not line.strip() or line.startswith("#"):
                continue
            item = json.loads(line)
            if not isinstance(item, dict):
                raise ValueError(f"Expected object in {path}:{ln}")
            yield ln, item


def read_csv(path: Path):
    with path.open(newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, columns, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def iso_utc(ts):
    return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat(timespec="microseconds")


def group_key(src, dst, port, proto, host, path):
    return str(src), str(dst), int(port), str(proto), str(host).lower(), str(path)


def group_key_from_csv(row):
    return group_key(row["src_ip"], row["dst_ip"], row["dst_port"], row["proto"], row["http_host"], row["uri_path"])


def semis(values):
    if values is None:
        return ""
    if isinstance(values, list):
        return ";".join(str(s) for s in values)
    return str(values)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo", type=Path, default=Path.cwd())
    p.add_argument("--source-ip", default="147.32.84.165")
    p.add_argument("--mz-ledger", type=Path, default=None, help="Optional manually reviewed PCAP MZ ledger CSV")
    args = p.parse_args()
    repo = args.repo.expanduser().resolve()
    logs = repo / "data/processed/scenario-01-neris/zeek"
    outdir = repo / "reports/week2/quy/generated"
    connpath, httppath = logs / "conn.log", logs / "http.log"
    inputs = {rule: outdir / fname for rule, fname in RULES.items()}
    for file in [connpath, httppath, *inputs.values()]:
        if not file.is_file():
            p.error(f"Missing required input: {file}")

    conn = {}
    for _, r in read_json_lines(connpath):
        uid = str(r.get("uid") or "")
        if uid:
            if uid in conn:
                raise ValueError(f"Duplicate conn.log UID {uid}")
            conn[uid] = r

    t1571_rows = read_csv(inputs["t1571"])
    t1071_rows = read_csv(inputs["t1071_001"])
    t1105_rows = read_csv(inputs["t1105"])
    t1571_keys = {group_key_from_csv(x) for x in t1571_rows}
    t1071_keys = {group_key_from_csv(x) for x in t1071_rows}
    # Per-event exact matcher: do NOT use sample UID lists from grouped CSVs.
    t1105_events = Counter((r["zeek_uid"], r["timestamp_utc"], r["src_ip"], r["dst_ip"],
                            int(r["dst_port"]), r["http_host"].lower(), r["uri_path"])
                           for r in t1105_rows)
    if len(t1571_keys) != len(t1571_rows) or len(t1071_keys) != len(t1071_rows):
        raise ValueError("Duplicate rule group keys; inspect detector output")
    if any(n != 1 for n in t1105_events.values()):
        raise ValueError("Duplicate T1105 event keys; inspect executable_ingress_events.csv")

    ledger = {}
    if args.mz_ledger:
        ledger_path = args.mz_ledger.expanduser()
        if not ledger_path.is_absolute():
            ledger_path = repo / ledger_path
        for r in read_csv(ledger_path):
            key = (r["zeek_uid"], r["dst_ip"], int(r["dst_port"]), r["uri_path"])
            if key in ledger:
                raise ValueError(f"Duplicate MZ ledger record {key}")
            if r.get("mz_hex_prefix", "").lower().replace(":", "").replace(" ", "")[:4] != "4d5a":
                raise ValueError(f"Ledger lacks expected 4d5a prefix for UID {r['zeek_uid']}")
            ledger[key] = r

    rows, triggered = [], []
    matched_groups = {"t1571": Counter(), "t1071_001": Counter()}
    matched_t1105 = Counter()
    matched_ledger = set()
    join_missing = 0
    for line_no, h in read_json_lines(httppath):
        uid = str(h.get("uid") or "")
        c = conn.get(uid)
        if c is None:
            join_missing += 1
            continue
        if str(c.get("id.orig_h") or "") != args.source_ip:
            continue
        ts_utc = iso_utc(h["ts"])
        src_ip, dst_ip = str(c["id.orig_h"]), str(c["id.resp_h"])
        dst_port = int(c["id.resp_p"])
        proto = str(c.get("proto") or "")
        host = str(h.get("host") or "").lower()
        uri_path = urlsplit(str(h.get("uri") or "")).path or "/"
        key = group_key(src_ip, dst_ip, dst_port, proto, host, uri_path)
        is_t1571 = key in t1571_keys
        is_t1071 = key in t1071_keys
        event_key = (uid, ts_utc, src_ip, dst_ip, dst_port, host, uri_path)
        is_t1105 = t1105_events[event_key] > 0
        if is_t1105:
            matched_t1105[event_key] += 1
        if is_t1571:
            matched_groups["t1571"][key] += 1
        if is_t1071:
            matched_groups["t1071_001"][key] += 1
        if is_t1571 and dst_port in WEB_STANDARD_PORTS:
            raise ValueError(f"T1571 group on standard port: {key}")
        match_ledger_key = (uid, dst_ip, dst_port, uri_path)
        evidence = ledger.get(match_ledger_key)
        if evidence:
            if not is_t1105:
                raise ValueError(f"MZ evidence UID {uid} not detected by T1105")
            matched_ledger.add(match_ledger_key)
        rules = [name for flag, name in ((is_t1571, "T1571"), (is_t1071, "T1071.001"), (is_t1105, "T1105")) if flag]
        transaction_id = f"S01-HTTP-L{line_no:06d}"
        item = {
            "transaction_id": transaction_id, "http_log_line": line_no,
            "http_ts_utc": ts_utc, "zeek_uid": uid,
            "src_ip": src_ip, "src_port": c.get("id.orig_p", ""),
            "dst_ip": dst_ip, "dst_port": dst_port, "proto": proto,
            "http_host": host, "uri_path": uri_path,
            "http_method": str(h.get("method") or "").upper(),
            "http_status": h.get("status_code", ""), "response_body_len": h.get("response_body_len", ""),
            "conn_state": c.get("conn_state", ""), "http_response_fuids": semis(h.get("resp_fuids")),
            "t1571": int(is_t1571), "t1071_001": int(is_t1071), "t1105": int(is_t1105),
            "triggered_rules": ";".join(rules),
            "mz_packet_verified": "yes" if evidence else "not_reviewed",
            "mz_evidence_frame": evidence.get("response_frame", "") if evidence else "",
            "mz_evidence_tcp_stream": evidence.get("tcp_stream", "") if evidence else "",
            "mz_evidence_note": evidence.get("note", "") if evidence else "",
            "ground_truth_label": "", "alignment_status": "not_attempted",
            "alignment_evidence": "", "evaluation_status": "unlabeled_not_scored",
        }
        rows.append(item)
        for rule in rules:
            triggered.append({
                "transaction_id": transaction_id, "zeek_uid": uid, "http_ts_utc": ts_utc,
                "rule": rule, "dst_ip": dst_ip, "dst_port": dst_port,
                "http_host": host, "uri_path": uri_path,
            })

    if join_missing:
        raise ValueError(f"There were {join_missing} HTTP logs without conn.log match")
    for rule, rule_rows, counts in (("t1571", t1571_rows, matched_groups["t1571"]),
                                    ("t1071_001", t1071_rows, matched_groups["t1071_001"])):
        for row in rule_rows:
            key = group_key_from_csv(row)
            expected_count = int(row["http_request_count"] if rule == "t1571" else row["request_count"])
            if counts[key] != expected_count:
                raise ValueError(f"{rule} member count mismatch for {key}: observed={counts[key]}, expected={expected_count}")
    if matched_t1105 != t1105_events:
        raise ValueError(f"T1105 event join differs. Missing/multiple: {t1105_events - matched_t1105} / {matched_t1105 - t1105_events}")
    if ledger and matched_ledger != set(ledger):
        raise ValueError(f"Unmatched evidence ledger entries: {set(ledger)-matched_ledger}")

    write_csv(outdir / "http_transaction_alert_matrix.csv", COLUMNS, rows)
    write_csv(outdir / "http_alerts_long.csv", LONG_COLUMNS, triggered)
    print(f"HTTP transactions from {args.source_ip}: {len(rows)}")
    print(f"T1571 transaction alerts: {sum(r['t1571'] for r in rows)}")
    print(f"T1071.001 transaction alerts: {sum(r['t1071_001'] for r in rows)}")
    print(f"T1105 transaction alerts: {sum(r['t1105'] for r in rows)}")
    print(f"Unique transactions with at least one alert: {sum(bool(r['triggered_rules']) for r in rows)}")
    print(f"MZ evidence matched: {len(matched_ledger)}")
    print(f"T1571 groups verified: {len(t1571_rows)}, T1071.001 groups verified: {len(t1071_rows)}")
    print(f"Outputs: {outdir.relative_to(repo)}/http_transaction_alert_matrix.csv")
    print(f"         {outdir.relative_to(repo)}/http_alerts_long.csv")
    print("No ground-truth labels or TP/FP/Precision/Recall metrics assigned.")


if __name__ == "__main__":
    main()
