#!/usr/bin/env python3
"""NT140 Week 2 - exploratory T1071.001 HTTP behavioral candidates.

Uses JSON-lines Zeek conn.log and http.log from the SAME Zeek run.
Candidate heuristics (not ground truth, and NOT proof of command-and-control):
  1) repeated requests with a long hexadecimal query parameter;
  2) repeated POST requests with a moderate inter-arrival CV.

All thresholds are explicitly exploratory and MUST be reviewed on independent
labeled traffic before any efficacy claims. Detects HTTP only (not opaque TLS).
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean, pstdev, median
from urllib.parse import urlsplit, parse_qsl

HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")


def read_json_lines(path: Path):
    with path.open(encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip() or line.startswith("#"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                raise ValueError(f"Bad JSON at {path}:{lineno}") from e
            if not isinstance(obj, dict):
                raise ValueError(f"Expected object at {path}:{lineno}")
            yield obj


def iso_utc(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="microseconds")


def query_features(uri: str, min_hex_len: int):
    """Returns long-hex (name, value) pairs, parameter names and URI path."""
    parsed = urlsplit(uri)
    path = parsed.path or "/"
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    long_hex = [(key, val) for key, val in pairs
                if len(val) >= min_hex_len and HEX_RE.fullmatch(val)]
    return path, long_hex, [key for key, _ in pairs]


def consecutive_burst_sizes(events, gap_seconds: float):
    if not events:
        return []
    result = []
    count = 1
    for prev, curr in zip(events, events[1:]):
        if curr["ts"] - prev["ts"] > gap_seconds:
            result.append(count)
            count = 1
        else:
            count += 1
    result.append(count)
    return result


def summary_counts(values):
    c = Counter(values)
    return ";".join(f"{k if k else 'missing'}:{v}" for k, v in sorted(c.items()))


def detect(repo: Path, source_ip: str, min_requests: int,
           min_hex_len: int, min_hex_fraction: float,
           min_post_requests: int, min_post_fraction: float,
           max_post_cv: float, burst_gap_s: float):
    logs = repo / "data/processed/scenario-01-neris/zeek"
    conn_path, http_path = logs / "conn.log", logs / "http.log"
    if not conn_path.is_file() or not http_path.is_file():
        raise FileNotFoundError(f"Missing {conn_path} or {http_path}")

    conns = {}
    for conn in read_json_lines(conn_path):
        uid = conn.get("uid")
        if uid:
            if uid in conns:
                raise ValueError(f"Duplicate conn.log UID: {uid}")
            conns[uid] = conn

    groups = defaultdict(list)
    counts = Counter()
    for http in read_json_lines(http_path):
        counts["http_records"] += 1
        uid = http.get("uid")
        conn = conns.get(uid)
        if conn is None:
            counts["uid_join_misses"] += 1
            continue
        if str(conn.get("id.orig_h") or "") != source_ip:
            continue
        counts["source_http_records"] += 1
        try:
            ts = float(http["ts"])
            dst_port = int(conn["id.resp_p"])
        except (TypeError, ValueError, KeyError) as e:
            raise ValueError(f"Invalid timestamp/port in HTTP UID={uid}") from e
        uri = str(http.get("uri") or "")
        path, long_hex_pairs, query_names = query_features(uri, min_hex_len)
        key = (source_ip, str(conn.get("id.resp_h") or ""), dst_port,
               str(conn.get("proto") or ""),
               str(http.get("host") or "").lower(), path)
        try:
            reply_packets = float(conn.get("resp_pkts") or 0)
        except (TypeError, ValueError):
            reply_packets = 0.0
        groups[key].append({
            "ts": ts, "uid": str(uid),
            "method": str(http.get("method") or "").upper(),
            "http_status": str(http.get("status_code") or ""),
            "conn_state": str(conn.get("conn_state") or ""),
            "reply_packets_positive": reply_packets > 0,
            "hex_params": long_hex_pairs,
            "param_names": query_names,
        })

    rows = []
    for (src, dst, port, proto, host, path), events in groups.items():
        events.sort(key=lambda e: (e["ts"], e["uid"]))
        n = len(events)
        hex_requests = sum(bool(e["hex_params"]) for e in events)
        hex_ratio = hex_requests / n
        hex_lengths = [len(v) for e in events for _, v in e["hex_params"]]
        unique_hex_values = {v for e in events for _, v in e["hex_params"]}
        hex_param_names = sorted({k for e in events for k, _ in e["hex_params"]})
        post_count = sum(e["method"] == "POST" for e in events)
        post_ratio = post_count / n
        intervals = [curr["ts"] - prev["ts"] for prev, curr in zip(events, events[1:])]
        positive = [val for val in intervals if val > 0]
        cv = pstdev(positive) / mean(positive) if len(positive) >= 2 and mean(positive) > 0 else None
        hex_flag = n >= min_requests and hex_ratio >= min_hex_fraction and len(unique_hex_values) >= 3
        post_flag = (post_count >= min_post_requests and post_ratio >= min_post_fraction
                     and cv is not None and cv <= max_post_cv)
        if not (hex_flag or post_flag):
            continue
        bursts = consecutive_burst_sizes(events, burst_gap_s)
        triggers = []
        if hex_flag:
            triggers.append("repeated_long_hex_query")
        if post_flag:
            triggers.append("repeated_post_with_low_to_moderate_cv")
        unique_uids = list(dict.fromkeys(e["uid"] for e in events))
        rows.append({
            "rule_id": "HTTP_WEB_BEHAVIOR_V1",
            "attack_technique_hypothesis": "T1071.001",
            "classification": "candidate_needs_review",
            "validation_status": "unvalidated",
            "src_ip": src, "dst_ip": dst, "dst_port": port, "proto": proto,
            "http_host": host, "uri_path": path, "request_count": n,
            "unique_uid_count": len(unique_uids),
            "http_methods": summary_counts(e["method"] for e in events),
            "http_statuses": summary_counts(e["http_status"] for e in events),
            "conn_states": summary_counts(e["conn_state"] for e in events),
            "response_packet_ratio": round(sum(e["reply_packets_positive"] for e in events) / n, 6),
            "long_hex_request_count": hex_requests,
            "long_hex_request_fraction": round(hex_ratio, 6),
            "long_hex_value_unique_count": len(unique_hex_values),
            "long_hex_value_max_length": max(hex_lengths, default=0),
            "long_hex_parameter_names": ";".join(hex_param_names),
            "all_query_parameter_names": ";".join(sorted({k for e in events for k in e["param_names"]})),
            "post_request_count": post_count, "post_request_fraction": round(post_ratio, 6),
            "positive_interval_count": len(positive),
            "duplicate_or_nonpositive_interval_count": len(intervals) - len(positive),
            "mean_iat_s": round(mean(positive), 6) if positive else "",
            "median_iat_s": round(median(positive), 6) if positive else "",
            "cv_population": round(cv, 6) if cv is not None else "",
            "max_iat_s": round(max(positive), 6) if positive else "",
            "burst_gap_s": burst_gap_s,
            "burst_count": len(bursts), "burst_sizes": ";".join(map(str, bursts)),
            "first_seen_utc": iso_utc(events[0]["ts"]),
            "last_seen_utc": iso_utc(events[-1]["ts"]),
            "sample_zeek_uids": ";".join(unique_uids[:8]),
            "triggered_signals": ";".join(triggers),
            "reason": "Exploratory HTTP metadata pattern, requires packet and CTU-13 label review",
        })

    rows.sort(key=lambda r: (-r["request_count"], r["dst_ip"], r["dst_port"], r["uri_path"]))
    out = repo / "reports/week2/quy/generated/web_behavior_alerts.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "rule_id", "attack_technique_hypothesis", "classification", "validation_status",
        "src_ip", "dst_ip", "dst_port", "proto", "http_host", "uri_path",
        "request_count", "unique_uid_count", "http_methods", "http_statuses", "conn_states",
        "response_packet_ratio", "long_hex_request_count", "long_hex_request_fraction",
        "long_hex_value_unique_count", "long_hex_value_max_length", "long_hex_parameter_names",
        "all_query_parameter_names", "post_request_count", "post_request_fraction",
        "positive_interval_count", "duplicate_or_nonpositive_interval_count", "mean_iat_s",
        "median_iat_s", "cv_population", "max_iat_s", "burst_gap_s", "burst_count",
        "burst_sizes", "first_seen_utc", "last_seen_utc", "sample_zeek_uids",
        "triggered_signals", "reason",
    ]
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"HTTP records: {counts['http_records']}")
    print(f"HTTP UID join misses: {counts['uid_join_misses']}")
    print(f"HTTP records from {source_ip}: {counts['source_http_records']}")
    print(f"Endpoint + host + URI-path groups examined: {len(groups)}")
    print(f"T1071.001 candidate groups: {len(rows)}")
    print(f"  long-hex signal groups: {sum('repeated_long_hex_query' in r['triggered_signals'] for r in rows)}")
    print(f"  repeated-POST signal groups: {sum('repeated_post_with_low_to_moderate_cv' in r['triggered_signals'] for r in rows)}")
    print(f"Output: {out.relative_to(repo)}")
    for r in rows[:12]:
        print(f"  {r['dst_ip']}:{r['dst_port']} {r['http_host']} {r['uri_path']} "
              f"requests={r['request_count']} CV={r['cv_population']} "
              f"bursts={r['burst_sizes']} triggers={r['triggered_signals']}")
    print("NOTE: candidate observations only; NO CTU-13 labels, TP/FP or confirmed C2 are inferred.")
    return rows


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo", type=Path, default=Path.cwd())
    p.add_argument("--source-ip", default="147.32.84.165")
    p.add_argument("--min-requests", type=int, default=4)
    p.add_argument("--min-hex-len", type=int, default=64)
    p.add_argument("--min-hex-fraction", type=float, default=0.75)
    p.add_argument("--min-post-requests", type=int, default=10)
    p.add_argument("--min-post-fraction", type=float, default=0.8)
    p.add_argument("--max-post-cv", type=float, default=0.8)
    p.add_argument("--burst-gap-s", type=float, default=60.0)
    a = p.parse_args()
    if a.min_requests < 2 or a.min_hex_len < 2 or a.min_post_requests < 2:
        p.error("min request/hex thresholds must be >= 2")
    if not (0 <= a.min_hex_fraction <= 1 and 0 <= a.min_post_fraction <= 1):
        p.error("fractions must be in [0, 1]")
    if a.max_post_cv < 0 or a.burst_gap_s <= 0:
        p.error("max-post-cv must be nonnegative and burst-gap-s positive")
    detect(a.repo.expanduser().resolve(), a.source_ip, a.min_requests,
           a.min_hex_len, a.min_hex_fraction, a.min_post_requests,
           a.min_post_fraction, a.max_post_cv, a.burst_gap_s)


if __name__ == "__main__":
    main()
