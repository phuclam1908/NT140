"""Inspect unmatched HTTP C2 Zeek connections for same-5-tuple Argus flow overlap.

This is a diagnostic probe, not a general-purpose ground-truth labeling tool.
"""
from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "reports/week1/generated"
CONN = ROOT / "data/processed/scenario-01-neris/zeek/conn.log"
FLOW = OUT / "neris_labeled_flows.csv"
UNMATCHED = OUT / "http_c2_unmatched_zeek.csv"

z = pd.read_json(CONN, lines=True)
unmatched = pd.read_csv(UNMATCHED, dtype={"uid": str})
flows = pd.read_csv(FLOW, dtype=str)
flows["flow_start_utc"] = (
    pd.to_datetime(flows["StartTime"], format="%Y/%m/%d %H:%M:%S.%f", errors="coerce")
    .dt.tz_localize("Europe/Prague", ambiguous="NaT", nonexistent="NaT")
    .dt.tz_convert("UTC")
)
flows["dur_s"] = pd.to_numeric(flows["Dur"], errors="coerce")
flows["flow_end_utc"] = flows["flow_start_utc"] + pd.to_timedelta(flows["dur_s"], unit="s")

rows = []
for uid in unmatched["uid"]:
    found = z.loc[z["uid"] == uid]
    if found.empty:
        continue
    c = found.iloc[0]
    zstart = pd.to_datetime(c["ts"], unit="s", utc=True)
    zend = zstart + pd.to_timedelta(c["duration"], unit="s")
    same = flows.loc[
        (flows["SrcAddr"] == str(c["id.orig_h"]))
        & (flows["DstAddr"] == str(c["id.resp_h"]))
        & (flows["Sport"].str.strip() == str(c["id.orig_p"]))
        & (flows["Dport"].str.strip() == str(c["id.resp_p"]))
        & (flows["Proto"].str.strip().str.lower() == str(c["proto"]).lower())
    ].copy()
    for _, f in same.iterrows():
        overlap = (f["flow_start_utc"] <= zend) and (f["flow_end_utc"] >= zstart)
        same_zeek_count = int((
            (z["id.orig_h"] == c["id.orig_h"])
            & (z["id.orig_p"] == c["id.orig_p"])
            & (z["id.resp_h"] == c["id.resp_h"])
            & (z["id.resp_p"] == c["id.resp_p"])
            & (z["proto"] == c["proto"])
        ).sum())
        rows.append({
            "uid": uid, "sport": int(c["id.orig_p"]), "zeek_start_utc": zstart.isoformat(),
            "zeek_end_utc": zend.isoformat(), "argus_start_utc": f["flow_start_utc"].isoformat(),
            "argus_end_utc": f["flow_end_utc"].isoformat(), "overlap": overlap,
            "same_5tuple_zeek_count": same_zeek_count, "label": f["Label"],
        })

result = pd.DataFrame(rows)
result.to_csv(OUT / "http_c2_exception_overlap.csv", index=False)
print("===== UNMATCHED CONNECTION / ARGUS OVERLAP =====")
print("Zeek connections without start-time match:", len(unmatched))
print("Same-5-tuple Argus records inspected:", len(result))
if not result.empty:
    print(result.to_string(index=False))
print("Saved:", OUT / "http_c2_exception_overlap.csv")
