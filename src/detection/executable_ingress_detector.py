#!/usr/bin/env python3
"""NT140 Week 2 - exploratory T1105 executable response candidates.

Reads JSON-lines Zeek conn.log, http.log, and (optionally) files.log from the
SAME Zeek extraction. Uses the HTTP transaction's response MIME metadata,
optional Zeek File Analysis metadata, URI extension, status and body length.

This script DOES NOT extract files, inspect raw MZ bytes, prove a complete
transfer, prove execution, or assign CTU-13 ground-truth / TP / FP labels.
"""
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

PE_MIMES = {"application/x-dosexec", "application/x-msdownload",
            "application/vnd.microsoft.portable-executable", "application/x-msdos-program"}
EXEC_SUFFIXES = (".exe", ".dll", ".scr", ".sys")

EVENT_COLUMNS = [
    "rule_id", "attack_technique_hypothesis", "classification", "validation_status",
    "evidence_level", "reason", "timestamp_utc", "zeek_uid", "src_ip", "src_port",
    "dst_ip", "dst_port", "proto", "conn_state", "http_host", "uri_path", "http_method",
    "http_status", "response_body_len", "http_detected_mime_types", "response_fuids",
    "files_log_matched_fuids", "files_detected_mime_types", "files_seen_bytes",
    "files_total_bytes", "files_missing_bytes", "files_log_available",
    "raw_mz_verified", "download_complete_verified", "execution_verified",
]
GROUP_COLUMNS = [
    "rule_id", "attack_technique_hypothesis", "classification", "validation_status",
    "src_ip", "dst_ip", "dst_port", "proto", "http_host", "uri_path",
    "http_request_count", "unique_uid_count", "first_seen_utc", "last_seen_utc",
    "reported_response_body_bytes_sum", "http_statuses", "http_detected_mime_types",
    "files_detected_mime_types", "pe_mime_transaction_count", "extension_only_transaction_count",
    "sample_zeek_uids", "sample_response_fuids", "reason", "raw_mz_verified",
    "download_complete_verified", "execution_verified",
]


def read_zeek_json(path: Path):
    with path.open(encoding="utf-8") as stream:
        for lineno, line in enumerate(stream, 1):
            if not line.strip() or line.startswith("#"):
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Bad JSON at {path}:{lineno}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"Expected JSON object at {path}:{lineno}")
            yield value


def as_list(obj):
    if obj is None:
        return []
    if isinstance(obj, list):
        return [str(item) for item in obj if item is not None]
    return [str(obj)]


def number_or_none(obj):
    if obj is None or obj == "":
        return None
    try:
        result = int(obj)
    except (TypeError, ValueError):
        return None
    return result if result >= 0 else None


def utc(ts):
    return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat(timespec="microseconds")


def semis(values):
    return ";".join(sorted(set(str(v) for v in values if str(v))))


def csv_write(path: Path, columns: list[str], records: list[dict]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(records)


def run(repo: Path, source_ip: str, min_body_bytes: int = 1):
    logs = repo / "data/processed/scenario-01-neris/zeek"
    conn_path, http_path, files_path = (logs / name for name in ("conn.log", "http.log", "files.log"))
    if not conn_path.is_file() or not http_path.is_file():
        raise FileNotFoundError(f"Need both conn.log and http.log in {logs}")

    conn_by_uid = {}
    for conn in read_zeek_json(conn_path):
        uid = conn.get("uid")
        if uid:
            if uid in conn_by_uid:
                raise ValueError(f"Duplicate conn.log uid: {uid}")
            conn_by_uid[uid] = conn

    file_by_fuid = {}
    if files_path.is_file():
        for entry in read_zeek_json(files_path):
            fuid = entry.get("fuid")
            if fuid:
                if fuid in file_by_fuid:
                    raise ValueError(f"Duplicate files.log fuid: {fuid}")
                file_by_fuid[fuid] = entry

    counters = Counter()
    events = []
    for http in read_zeek_json(http_path):
        counters["http_records"] += 1
        uid = http.get("uid")
        conn = conn_by_uid.get(uid)
        if conn is None:
            counters["uid_join_misses"] += 1
            continue
        if str(conn.get("id.orig_h") or "") != source_ip:
            continue
        counters["source_http_records"] += 1
        body_len = number_or_none(http.get("response_body_len"))
        status_code = number_or_none(http.get("status_code"))
        if body_len is None or body_len < min_body_bytes or not (status_code and 200 <= status_code < 300):
            continue

        resp_fuids = as_list(http.get("resp_fuids"))
        matched = [(fuid, file_by_fuid[fuid]) for fuid in resp_fuids if fuid in file_by_fuid]
        http_mimes = as_list(http.get("resp_mime_types"))
        file_mimes = [f.get("mime_type") for _, f in matched if f.get("mime_type")]
        pe_http = any(m.lower() in PE_MIMES for m in http_mimes)
        pe_file = any(str(m).lower() in PE_MIMES for m in file_mimes)
        uri = str(http.get("uri") or "")
        uri_path = urlsplit(uri).path or "/"
        extension = uri_path.lower().endswith(EXEC_SUFFIXES)
        if not (pe_http or pe_file or extension):
            continue
        try:
            timestamp = utc(http["ts"])
            dst_port = int(conn["id.resp_p"])
        except (ValueError, TypeError, KeyError) as exc:
            raise ValueError(f"Invalid timestamp or port in http UID={uid}") from exc

        pe_detected = pe_http or pe_file
        reason = ("Zeek recognized Windows executable-like response MIME; "
                  "HTTP response has body and successful status" if pe_detected else
                  "Executable-like URI suffix, successful HTTP response and body; "
                  "no executable MIME evidence from Zeek")

        def sum_optional(field):
            vals = [number_or_none(f.get(field)) for _, f in matched]
            vals = [v for v in vals if v is not None]
            return sum(vals) if vals else ""

        events.append({
            "rule_id": "HTTP_EXECUTABLE_RESPONSE_V1",
            "attack_technique_hypothesis": "T1105",
            "classification": "candidate_needs_review",
            "validation_status": "unvalidated",
            "evidence_level": "zeek_pe_mime" if pe_detected else "uri_extension_only",
            "reason": reason,
            "timestamp_utc": timestamp,
            "zeek_uid": str(uid),
            "src_ip": source_ip,
            "src_port": conn.get("id.orig_p", ""),
            "dst_ip": str(conn.get("id.resp_h") or ""),
            "dst_port": dst_port,
            "proto": str(conn.get("proto") or ""),
            "conn_state": str(conn.get("conn_state") or ""),
            "http_host": str(http.get("host") or "").lower(),
            "uri_path": uri_path,
            "http_method": str(http.get("method") or "").upper(),
            "http_status": status_code,
            "response_body_len": body_len,
            "http_detected_mime_types": semis(http_mimes),
            "response_fuids": semis(resp_fuids),
            "files_log_matched_fuids": semis(fuid for fuid, _ in matched),
            "files_detected_mime_types": semis(file_mimes),
            "files_seen_bytes": sum_optional("seen_bytes"),
            "files_total_bytes": sum_optional("total_bytes"),
            "files_missing_bytes": sum_optional("missing_bytes"),
            "files_log_available": str(files_path.is_file()).lower(),
            "raw_mz_verified": "no",
            "download_complete_verified": "no",
            "execution_verified": "no",
        })
        counters["pe_mime_transaction_count" if pe_detected else "extension_only_transaction_count"] += 1

    events.sort(key=lambda e: (e["timestamp_utc"], e["zeek_uid"]))
    groups = defaultdict(list)
    for event in events:
        key = (event["src_ip"], event["dst_ip"], event["dst_port"],
               event["proto"], event["http_host"], event["uri_path"])
        groups[key].append(event)
    summaries = []
    for key, values in groups.items():
        first = values[0]
        all_mimes = [v for e in values for v in e["http_detected_mime_types"].split(";") if v]
        file_mimes = [v for e in values for v in e["files_detected_mime_types"].split(";") if v]
        fuid_vals = [v for e in values for v in e["response_fuids"].split(";") if v]
        ids = list(dict.fromkeys(e["zeek_uid"] for e in values))
        statuses = Counter(e["http_status"] for e in values)
        summaries.append({
            "rule_id": "HTTP_EXECUTABLE_RESPONSE_V1",
            "attack_technique_hypothesis": "T1105",
            "classification": "candidate_needs_review",
            "validation_status": "unvalidated",
            "src_ip": key[0], "dst_ip": key[1], "dst_port": key[2],
            "proto": key[3], "http_host": key[4], "uri_path": key[5],
            "http_request_count": len(values), "unique_uid_count": len(ids),
            "first_seen_utc": values[0]["timestamp_utc"],
            "last_seen_utc": values[-1]["timestamp_utc"],
            "reported_response_body_bytes_sum": sum(e["response_body_len"] for e in values),
            "http_statuses": ";".join(f"{k}:{v}" for k, v in sorted(statuses.items())),
            "http_detected_mime_types": semis(all_mimes),
            "files_detected_mime_types": semis(file_mimes),
            "pe_mime_transaction_count": sum(e["evidence_level"] == "zeek_pe_mime" for e in values),
            "extension_only_transaction_count": sum(e["evidence_level"] == "uri_extension_only" for e in values),
            "sample_zeek_uids": ";".join(ids[:8]),
            "sample_response_fuids": ";".join(sorted(set(fuid_vals))[:8]),
            "reason": "Exploratory HTTP executable-response metadata; no raw file bytes examined",
            "raw_mz_verified": "no",
            "download_complete_verified": "no",
            "execution_verified": "no",
        })
    summaries.sort(key=lambda r: (-r["pe_mime_transaction_count"], -r["http_request_count"],
                                  r["dst_ip"], r["uri_path"]))

    outdir = repo / "reports/week2/quy/generated"
    csv_write(outdir / "executable_ingress_events.csv", EVENT_COLUMNS, events)
    csv_write(outdir / "executable_ingress_candidates.csv", GROUP_COLUMNS, summaries)
    print(f"HTTP records: {counters['http_records']}")
    print(f"UID join misses: {counters['uid_join_misses']}")
    print(f"HTTP records from {source_ip}: {counters['source_http_records']}")
    print(f"files.log available: {files_path.is_file()} (FUIDs indexed: {len(file_by_fuid)})")
    print(f"T1105 executable-response candidate transactions: {len(events)}")
    print(f"  Zeek PE MIME transactions: {counters['pe_mime_transaction_count']}")
    print(f"  URI-extension-only transactions: {counters['extension_only_transaction_count']}")
    print(f"Candidate groups: {len(summaries)}")
    print(f"Outputs: {outdir.relative_to(repo)}/executable_ingress_{{events,candidates}}.csv")
    for row in summaries[:10]:
        print(f"  {row['dst_ip']}:{row['dst_port']} {row['http_host']} {row['uri_path']} "
              f"requests={row['http_request_count']} PE_MIME={row['pe_mime_transaction_count']} "
              f"body_bytes_sum={row['reported_response_body_bytes_sum']}")
    print("NOTE: NO MZ signature verification, complete-download proof, execution proof, or TP/FP labels.")
    return events, summaries


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--source-ip", default="147.32.84.165")
    parser.add_argument("--min-body-bytes", type=int, default=1)
    options = parser.parse_args()
    if options.min_body_bytes < 1:
        parser.error("--min-body-bytes must be positive")
    run(options.repo.expanduser().resolve(), options.source_ip, options.min_body_bytes)


if __name__ == "__main__":
    main()
