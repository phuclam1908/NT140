"""Probe matching of CTU-13 Scenario 1 Zeek conn records to Argus flows.

Diagnostic only; matching is restricted to a known HTTP C2 candidate.
Run from any working directory with: python src/analysis/http_c2_flow_alignment.py
"""
from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
ZEEK_PATH = ROOT / "data/processed/scenario-01-neris/zeek/conn.log"
FLOW_PATH = ROOT / "reports/week1/generated/neris_labeled_flows.csv"
OUT_DIR = ROOT / "reports/week1/generated"
OUT_DIR.mkdir(parents=True, exist_ok=True)

SRC_IP = "147.32.84.165"
DST_IP = "31.192.109.167"
DST_PORT = 80
TOLERANCE_S = 2.0  # Exploratory tolerance; not a validated universal threshold.

z = pd.read_json(ZEEK_PATH, lines=True)
z = z.loc[
    (z["id.orig_h"] == SRC_IP)
    & (z["id.resp_h"] == DST_IP)
    & (z["id.resp_p"] == DST_PORT)
    & (z["proto"].astype(str).str.lower() == "tcp"),
    ["uid", "ts", "id.orig_p", "id.resp_p", "proto", "conn_state", "duration"],
].copy()
z = z.rename(columns={
    "id.orig_p": "sport", "id.resp_p": "dport", "conn_state": "zeek_conn_state",
    "duration": "zeek_duration_s",
})
z["sport"] = pd.to_numeric(z["sport"], errors="coerce").astype("Int64")
z["dport"] = pd.to_numeric(z["dport"], errors="coerce").astype("Int64")
z["proto"] = z["proto"].astype(str).str.strip().str.lower()
z["zeek_time_utc"] = pd.to_datetime(z["ts"], unit="s", utc=True)

f = pd.read_csv(FLOW_PATH, dtype=str, low_memory=False)
f = f.loc[
    (f["SrcAddr"].str.strip() == SRC_IP)
    & (f["DstAddr"].str.strip() == DST_IP)
    & (pd.to_numeric(f["Dport"], errors="coerce") == DST_PORT)
    & (f["Proto"].str.strip().str.lower() == "tcp")
].copy().reset_index(drop=True)
f["flow_row"] = f.index
f["sport"] = pd.to_numeric(f["Sport"], errors="coerce").astype("Int64")
f["dport"] = pd.to_numeric(f["Dport"], errors="coerce").astype("Int64")
f["proto"] = f["Proto"].str.strip().str.lower()
f["flow_time_utc"] = (
    pd.to_datetime(f["StartTime"], format="%Y/%m/%d %H:%M:%S.%f", errors="coerce")
    .dt.tz_localize("Europe/Prague", ambiguous="NaT", nonexistent="NaT")
    .dt.tz_convert("UTC")
)

# Restrict candidates to exact protocol and ports; endpoints are already filtered.
candidates = z.merge(
    f[["flow_row", "sport", "dport", "proto", "flow_time_utc", "Label", "Dur"]],
    on=["sport", "dport", "proto"],
    how="inner",
)
candidates["delta_s"] = (
    candidates["flow_time_utc"] - candidates["zeek_time_utc"]
).dt.total_seconds()
candidates = candidates.loc[candidates["delta_s"].abs() <= TOLERANCE_S].copy()

# Never silently pick one of several candidate records.
uid_counts = candidates["uid"].value_counts()
flow_counts = candidates["flow_row"].value_counts()
candidates["unique_pair"] = (
    candidates["uid"].map(uid_counts).eq(1)
    & candidates["flow_row"].map(flow_counts).eq(1)
)
verified_candidates = candidates.loc[candidates["unique_pair"]].copy()
verified_candidates = verified_candidates.sort_values("zeek_time_utc")

report_columns = [
    "uid", "sport", "dport", "proto", "zeek_time_utc", "flow_time_utc",
    "delta_s", "zeek_duration_s", "Dur", "Label", "unique_pair",
]
candidates.sort_values(["zeek_time_utc", "delta_s"]).to_csv(
    OUT_DIR / "http_c2_alignment_candidates.csv", columns=report_columns, index=False
)

unmatched = z.loc[~z["uid"].isin(verified_candidates["uid"])].copy()
unmatched.sort_values("zeek_time_utc").to_csv(
    OUT_DIR / "http_c2_unmatched_zeek.csv", index=False
)

print("===== HTTP C2 FLOW ALIGNMENT PROBE =====")
print("Zeek connections:", len(z))
print("Argus labeled flows (same endpoints / protocol / port):", len(f))
print(f"Candidate pairs within {TOLERANCE_S:g}s:", len(candidates))
print("One-to-one unambiguous pairs:", len(verified_candidates))
print("Zeek connections without unambiguous match:", len(unmatched))
print("Argus flows without unambiguous match:", len(f) - verified_candidates["flow_row"].nunique())
if not verified_candidates.empty:
    print("\nLabel distribution among one-to-one pairs:")
    print(verified_candidates["Label"].value_counts().to_string())
    print("\nTime offsets (flow - Zeek, seconds):")
    print(verified_candidates["delta_s"].describe().to_string())
if not unmatched.empty:
    print("\nUnmatched / ambiguous Zeek records:")
    print(unmatched[["uid", "sport", "zeek_time_utc", "zeek_conn_state", "zeek_duration_s"]].to_string(index=False))
print("\nOutputs:")
print(OUT_DIR / "http_c2_alignment_candidates.csv")
print(OUT_DIR / "http_c2_unmatched_zeek.csv")
