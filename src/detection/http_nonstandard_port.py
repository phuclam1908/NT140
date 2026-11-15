#!/usr/bin/env python3
"""NT140 week 2 — candidate HTTP on non-standard destination ports.

Rule hypothesis: MITRE ATT&CK T1571 (Non-Standard Port).
Source: JSON-lines Zeek conn.log + http.log from the same extraction.
This is a behavioral flag; it is NOT a ground-truth verdict, malware label,
or confirmation that T1571 occurred.
"""
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


def read_json_lines(path: Path):
    with path.open(encoding="utf-8") as handle:
        for i, line in enumerate(handle, start=1):
            if not line.strip() or line.startswith("#"):
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON line at {path}:{i}") from exc


def utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="microseconds")


def run(repo: Path, src: str, standard_ports: set[int]) -> None:
    logs = repo / "data/processed/scenario-01-neris/zeek"
    conns_file, http_file = logs / "conn.log", logs / "http.log"
    if not conns_file.is_file() or not http_file.is_file():
        raise FileNotFoundError("Expected conn.log and http.log in " + str(logs))

    conns = {}
    for c in read_json_lines(conns_file):
        uid = c.get("uid")
        if uid is not None:
            if uid in conns:
                raise ValueError(f"Duplicate Zeek UID in conn.log: {uid}")
            conns[uid] = c

    groups = defaultdict(list)
    total_http = 0
    missing_join = 0
    infected_http = 0
    unusual_http = 0
    for h in read_json_lines(http_file):
        total_http += 1
        c = conns.get(h.get("uid"))
        if c is None:
            missing_join += 1
            continue
        if str(c.get("id.orig_h", "")) != src:
            continue
        infected_http += 1
        try:
            port = int(c.get("id.resp_p"))
            ts = float(h["ts"])
        except (ValueError, TypeError, KeyError) as exc:
            raise ValueError(f"Missing/invalid HTTP destination port or timestamp, UID {h.get('uid')}") from exc
        if port in standard_ports:
            continue
        unusual_http += 1
        uri = str(h.get("uri") or "")
        path = uri.split("?", 1)[0]
        key = (
            str(c.get("id.orig_h") or ""),
            str(c.get("id.resp_h") or ""),
            port,
            str(c.get("proto") or ""),
            str(h.get("host") or "").lower(),
            path,
        )
        groups[key].append({
            "ts": ts,
            "uid": str(h.get("uid") or ""),
            "method": str(h.get("method") or ""),
            "status": str(h.get("status_code") or ""),
            "conn_state": str(c.get("conn_state") or ""),
            "uri": uri,
        })

    header = [
        "rule_id", "attack_technique_hypothesis", "classification", "src_ip", "dst_ip",
        "dst_port", "proto", "http_host", "uri_path", "http_request_count", "unique_uid_count",
        "first_seen_utc", "last_seen_utc", "http_methods", "http_statuses", "conn_states",
        "sample_zeek_uids", "reason", "validation_status",
    ]
    rows = []
    for (sip, dip, port, proto, host, path), events in groups.items():
        events.sort(key=lambda e: (e["ts"], e["uid"]))
        def fmt_count(field):
            return ";".join(f"{k or 'missing'}:{v}" for k, v in sorted(Counter(e[field] for e in events).items()))
        uids = list(dict.fromkeys(e["uid"] for e in events))
        rows.append({
            "rule_id": "HTTP_NONSTANDARD_PORT_V1",
            "attack_technique_hypothesis": "T1571",
            "classification": "candidate_needs_review",
            "src_ip": sip, "dst_ip": dip, "dst_port": port, "proto": proto,
            "http_host": host, "uri_path": path,
            "http_request_count": len(events), "unique_uid_count": len(uids),
            "first_seen_utc": utc(events[0]["ts"]), "last_seen_utc": utc(events[-1]["ts"]),
            "http_methods": fmt_count("method"), "http_statuses": fmt_count("status"),
            "conn_states": fmt_count("conn_state"), "sample_zeek_uids": ";".join(uids[:5]),
            "reason": f"Zeek recognized HTTP to destination port {port}; not in configured web-port allowlist",
            "validation_status": "unvalidated",
        })
    rows.sort(key=lambda r: (-r["http_request_count"], r["dst_ip"], r["dst_port"], r["uri_path"]))

    out = repo / "reports/week2/quy/generated/nonstandard_http_port_alerts.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=header)
        writer.writeheader()
        writer.writerows(rows)

    print(f"HTTP records: {total_http}")
    print(f"UID join misses: {missing_join}")
    print(f"HTTP records from {src}: {infected_http}")
    print(f"Non-standard-port HTTP requests: {unusual_http}")
    print(f"Alert candidate groups: {len(rows)}")
    print(f"Output: {out.relative_to(repo)}")
    print("Note: these are candidate observations, not confirmed malware or FP/TP metrics.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--source-ip", default="147.32.84.165")
    parser.add_argument("--standard-ports", default="80,443,8080",
                        help="Comma-separated HTTP port allowlist for the Week 2 exploratory rule")
    args = parser.parse_args()
    ports = {int(p.strip()) for p in args.standard_ports.split(",") if p.strip()}
    if not ports or any(p < 1 or p > 65535 for p in ports):
        parser.error("Invalid --standard-ports")
    run(args.repo.expanduser().resolve(), args.source_ip, ports)


if __name__ == "__main__":
    main()
