#!/usr/bin/env python3
"""NT140 Week 2: inspect Neris HTTP /sn.php request inter-arrival times.

Input: JSON-lines Zeek conn.log + http.log from the SAME Zeek extraction.
Output: request timeline, grouped statistics, plot, and a draft markdown report.
This is descriptive analysis, NOT malware/C2 verification or ground-truth scoring.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

EVENT_FIELDS = [
    "ts", "timestamp_utc", "uid", "src_ip", "dst_ip", "dst_port", "protocol",
    "host", "uri_path", "uri", "method", "http_status", "conn_state",
    "request_body_len", "response_body_len", "iat_s",
]
GROUP_KEYS = ["src_ip", "dst_ip", "dst_port", "protocol", "host", "uri_path"]
SUMMARY_FIELDS = GROUP_KEYS + [
    "request_count", "positive_interval_count", "duplicate_timestamp_count",
    "mean_iat_s", "median_iat_s", "std_population_iat_s", "cv_population",
    "min_iat_s", "p25_iat_s", "p75_iat_s", "max_iat_s",
    "http_200_count", "first_seen_utc", "last_seen_utc", "interpretation",
]


def json_lines(path: Path):
    with path.open("r", encoding="utf-8") as file:
        for lineno, line in enumerate(file, 1):
            if not line.strip() or line.startswith("#"):
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{lineno}: log is not valid JSON-lines") from exc


def utc_str(ts: float) -> str:
    return pd.to_datetime(ts, unit="s", utc=True).isoformat()


def number_or_blank(value):
    try:
        return float(value) if value is not None and str(value) != "-" else np.nan
    except (TypeError, ValueError):
        return np.nan


def analyze(repo: Path, source_ip: str, uri_pattern: str, min_requests: int) -> int:
    log_dir = repo / "data/processed/scenario-01-neris/zeek"
    http_log, conn_log = log_dir / "http.log", log_dir / "conn.log"
    for path in (http_log, conn_log):
        if not path.is_file():
            print(f"ERROR: Missing {path}", file=sys.stderr)
            return 2
    out_dir = repo / "reports/week2/quy"
    generated = out_dir / "generated"
    generated.mkdir(parents=True, exist_ok=True)
    try:
        regex = re.compile(uri_pattern, flags=re.IGNORECASE)
    except re.error as exc:
        print(f"ERROR: Invalid URI regex: {exc}", file=sys.stderr)
        return 2

    conn_by_uid = {}
    for row in json_lines(conn_log):
        if "uid" in row:
            uid = str(row["uid"])
            if uid in conn_by_uid:
                raise ValueError(f"Duplicate uid in conn.log: {uid}. Inspect Zeek extraction.")
            conn_by_uid[uid] = row

    events = []
    http_count, unjoined_count, wrong_source_count = 0, 0, 0
    for row in json_lines(http_log):
        http_count += 1
        uid = str(row.get("uid", ""))
        connection = conn_by_uid.get(uid)
        if connection is None:
            unjoined_count += 1
            continue
        if str(connection.get("id.orig_h", "")) != source_ip:
            wrong_source_count += 1
            continue
        uri = str(row.get("uri") or "")
        if not regex.search(uri):
            continue
        try:
            ts = float(row["ts"])
        except (ValueError, TypeError, KeyError) as exc:
            raise ValueError(f"HTTP record {uid} has invalid timestamp") from exc
        # URI path is used for grouping. Query parameters are retained in 'uri'.
        uri_path = uri.split("?", 1)[0]
        events.append({
            "ts": ts, "timestamp_utc": utc_str(ts), "uid": uid,
            "src_ip": source_ip,
            "dst_ip": str(connection.get("id.resp_h") or ""),
            "dst_port": str(connection.get("id.resp_p") or ""),
            "protocol": str(connection.get("proto") or ""),
            "host": str(row.get("host") or "").lower(),
            "uri_path": uri_path,
            "uri": uri, "method": str(row.get("method") or ""),
            "http_status": row.get("status_code"),
            "conn_state": str(connection.get("conn_state") or ""),
            "request_body_len": number_or_blank(row.get("request_body_len")),
            "response_body_len": number_or_blank(row.get("response_body_len")),
        })

    df = pd.DataFrame(events)
    if df.empty:
        df = pd.DataFrame(columns=EVENT_FIELDS)
        summary = pd.DataFrame(columns=SUMMARY_FIELDS)
    else:
        df = df.sort_values(GROUP_KEYS + ["ts", "uid"], kind="stable").reset_index(drop=True)
        # Same-second HTTP requests are counted, not discarded. Positive intervals only
        # are used for mean/std/CV; 0-second duplicate timestamps are separately counted.
        df["iat_s"] = df.groupby(GROUP_KEYS, dropna=False)["ts"].diff()
        summaries = []
        for key, group in df.groupby(GROUP_KEYS, dropna=False, sort=False):
            vals = group.loc[group["iat_s"] > 0, "iat_s"].to_numpy(dtype=float)
            n, pos_n = len(group), len(vals)
            avg = float(np.mean(vals)) if pos_n else np.nan
            std = float(np.std(vals, ddof=0)) if pos_n else np.nan
            cv = float(std / avg) if pos_n and avg > 0 else np.nan
            if n < min_requests or pos_n < min_requests - 1:
                interpretation = "insufficient_observations"
            elif cv < 0.3:
                interpretation = "low_cv_candidate_NOT_confirmed"
            else:
                interpretation = "higher_cv_not_strictly_periodic"
            summaries.append(dict(zip(GROUP_KEYS, key)) | {
                "request_count": n,
                "positive_interval_count": pos_n,
                "duplicate_timestamp_count": int((group["iat_s"] == 0).sum()),
                "mean_iat_s": avg, "median_iat_s": float(np.median(vals)) if pos_n else np.nan,
                "std_population_iat_s": std, "cv_population": cv,
                "min_iat_s": float(np.min(vals)) if pos_n else np.nan,
                "p25_iat_s": float(np.percentile(vals, 25)) if pos_n else np.nan,
                "p75_iat_s": float(np.percentile(vals, 75)) if pos_n else np.nan,
                "max_iat_s": float(np.max(vals)) if pos_n else np.nan,
                "http_200_count": int((pd.to_numeric(group["http_status"], errors="coerce") == 200).sum()),
                "first_seen_utc": utc_str(float(group["ts"].min())),
                "last_seen_utc": utc_str(float(group["ts"].max())),
                "interpretation": interpretation,
            })
        summary = pd.DataFrame(summaries, columns=SUMMARY_FIELDS)
        summary = summary.sort_values(["request_count", "dst_ip"], ascending=[False, True]).reset_index(drop=True)

    df.to_csv(generated / "sn_php_http_events.csv", index=False, columns=EVENT_FIELDS)
    summary.to_csv(generated / "sn_php_beaconing_summary.csv", index=False, columns=SUMMARY_FIELDS)

    plot_files = []
    if not summary.empty:
        top = summary.iloc[0]
        mask = pd.Series(True, index=df.index)
        for k in GROUP_KEYS:
            mask &= df[k] == top[k]
        group = df.loc[mask].copy().sort_values("ts")
        intervals = group.loc[group["iat_s"] > 0, "iat_s"]
        if not intervals.empty:
            fig, ax = plt.subplots(figsize=(9, 4.5))
            ax.hist(intervals, bins=min(25, max(5, int(np.sqrt(len(intervals))))))
            ax.set(title="/sn.php: positive HTTP request inter-arrival times (top group)", xlabel="IAT (seconds)", ylabel="Frequency")
            fig.tight_layout()
            name = "sn_php_iat_histogram.png"
            fig.savefig(generated / name, dpi=150)
            plt.close(fig)
            plot_files.append(name)
        fig, ax = plt.subplots(figsize=(9, 4.5))
        ax.scatter(range(1, len(group) + 1), (group["ts"] - float(group["ts"].min())) / 60.0, s=18)
        ax.set(title="/sn.php: request sequence vs elapsed time (top group)", xlabel="Request index", ylabel="Elapsed minutes")
        fig.tight_layout()
        name = "sn_php_request_scatter.png"
        fig.savefig(generated / name, dpi=150)
        plt.close(fig)
        plot_files.append(name)

    report = [
        "# Week 2 — Neris `/sn.php` HTTP timing analysis",
        "",
        "## Source and method",
        f"- Zeek input (JSON-lines): `{http_log.relative_to(repo)}`, `{conn_log.relative_to(repo)}` (same run; joined by `uid`).",
        f"- Infected source IP filter: `{source_ip}`. URI regex: `{uri_pattern}`.",
        "- Group key: source IP, destination IP:port, protocol, HTTP Host, URI path (without query string).",
        "- Times are Unix epoch seconds from Zeek, shown as UTC. IAT = consecutive HTTP request timestamp difference.",
        "- Statistics exclude zero-length IATs from mean/std/CV, but count duplicates separately.",
        "- Population standard deviation uses `ddof=0`; CV = std_population / mean_positive_IAT.",
        f"- Minimum request count for ranking: {min_requests}; threshold CV < 0.3 is an exploratory indicator only.",
        "",
        "## Data coverage",
        f"- HTTP records in file: **{http_count}**.",
        f"- HTTP records with no conn.log UID match: **{unjoined_count}**.",
        f"- HTTP records with a different originator: **{wrong_source_count}**.",
        f"- Selected Neris `/sn.php` HTTP requests: **{len(df)}** in **{len(summary)}** endpoint groups.",
        "",
        "## Results",
    ]
    if summary.empty:
        report += [
            "No matching HTTP records were found. Do not assume `/sn.php` is present in the current Scenario 1 Zeek logs.",
            "Check the case description, exact URI spelling, and whether the referenced traffic is from the same PCAP.",
        ]
    else:
        report += ["| Destination | Host | URI | Requests | Positive IATs | Median IAT (s) | CV | Interpretation |",
                   "|---|---|---|---:|---:|---:|---:|---|"]
        for _, row in summary.iterrows():
            median = "n/a" if pd.isna(row["median_iat_s"]) else f"{row['median_iat_s']:.3f}"
            cv = "n/a" if pd.isna(row["cv_population"]) else f"{row['cv_population']:.4f}"
            report.append(f"| `{row['dst_ip']}:{row['dst_port']}/{row['protocol']}` | `{row['host']}` | `{row['uri_path']}` | {int(row['request_count'])} | {int(row['positive_interval_count'])} | {median} | {cv} | {row['interpretation']} |")
        report += ["", "Top-group plots: " + ", ".join(f"`generated/{name}`" for name in plot_files) + "."]
    report += [
        "", "## Limits and validation needed",
        "- Low CV does **not** independently confirm C2 or an infected host's periodic beaconing; also assess protocol, failed/successful sessions, payload/packet evidence and benign alternatives.",
        "- A CV >= 0.3 also does **not** exclude C2: gaps and session failures can inflate dispersion.",
        "- No Argus ground-truth label mapping is performed here. Do not calculate TP/FP/Precision/Recall from this output.",
        "- Do not mark FND-002 `VALIDATED` solely on the basis of a CV threshold. Reconcile FND numbering between Week 1 and the newer plan.",
        "- A packet-level Wireshark review remains necessary before making content-level assertions.",
        "", "## Next review",
        "1. Check this summary against the current team Week 2 plan and existing Week 1 findings.",
        "2. Send the event timeline and summary to Lâm; agree on evaluation unit and label policy.",
        "3. Validate candidate traffic in Wireshark; use accepted examples to develop detection rules without leakage.",
        "",
    ]
    (out_dir / "beaconing_analysis.md").write_text("\n".join(report), encoding="utf-8")

    print(f"HTTP records read: {http_count}")
    print(f"HTTP UID join misses: {unjoined_count}")
    print(f"Neris /sn.php requests: {len(df)}")
    print(f"Endpoint groups: {len(summary)}")
    if not summary.empty:
        cols = ["dst_ip", "dst_port", "host", "request_count", "median_iat_s", "cv_population", "interpretation"]
        print(summary[cols].head(10).to_string(index=False))
    print(f"Outputs: {out_dir.relative_to(repo)}/beaconing_analysis.md and {generated.relative_to(repo)}/")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd(), help="NT140 repository root (default: current directory)")
    parser.add_argument("--source-ip", default="147.32.84.165")
    parser.add_argument("--uri-regex", default=r"(?:^|/)sn\.php(?:\?|$)")
    parser.add_argument("--min-requests", type=int, default=10)
    args = parser.parse_args()
    if args.min_requests < 3:
        parser.error("--min-requests must be >= 3")
    try:
        raise SystemExit(analyze(args.repo.expanduser().resolve(), args.source_ip, args.uri_regex, args.min_requests))
    except (OSError, ValueError, KeyError) as exc:
        parser.exit(2, f"ERROR: {exc}\n")


if __name__ == "__main__":
    main()
