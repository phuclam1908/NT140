"""Recreate HTTP C2 candidate evidence and POST-timing figure from Zeek JSON logs."""
from pathlib import Path
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[2]
LOG_DIR = ROOT / "data/processed/scenario-01-neris/zeek"
OUT = ROOT / "reports/week1/generated"
SRC = "147.32.84.165"
DST = "31.192.109.167"
HOST = "finalcortex.com"
URI = "/snapbn/gate.php"
OUT.mkdir(parents=True, exist_ok=True)

conn = pd.read_json(LOG_DIR / "conn.log", lines=True)
http = pd.read_json(LOG_DIR / "http.log", lines=True)
endpoint = conn.loc[
    (conn["id.orig_h"] == SRC)
    & (conn["id.resp_h"] == DST)
    & (conn["id.resp_p"] == 80)
    & (conn["proto"].astype(str).str.lower() == "tcp")
].copy()
requests = http.loc[http["uid"].isin(endpoint["uid"])].copy()
requests = requests.sort_values("ts")
requests.to_csv(OUT / "http_candidate_evidence.csv", index=False)

post = requests.loc[
    (requests["method"] == "POST")
    & (requests["host"] == HOST)
    & (requests["uri"] == URI)
].copy()
post["timestamp_utc"] = pd.to_datetime(post["ts"], unit="s", utc=True)
post["interval_s"] = pd.to_numeric(post["ts"], errors="coerce").diff()
post.to_csv(OUT / "http_post_timeline.csv", index=False)
intervals = post["interval_s"].dropna()
intervals = intervals.loc[intervals > 0]

if not intervals.empty:
    plt.figure(figsize=(12, 5))
    plt.plot(range(1, len(intervals) + 1), intervals, marker="o", markersize=4)
    plt.axhline(y=120, linestyle="--", label="120-second reference")
    plt.axhline(y=intervals.median(), linestyle="--", label=f"Median: {intervals.median():.2f}s")
    plt.title("Neris HTTP C2 POST Inter-arrival Times")
    plt.xlabel("Interval number")
    plt.ylabel("Inter-arrival time (seconds)")
    plt.grid(alpha=0.3)
    plt.legend()
    plt.tight_layout()
    plt.savefig(OUT / "http_post_intervals.png", dpi=150)
    plt.close()

print("===== HTTP C2 EVIDENCE =====")
print("Zeek endpoint connections:", len(endpoint))
print("HTTP records:", len(requests))
print("POST /snapbn/gate.php:", len(post))
print("Positive POST intervals:", len(intervals))
if not intervals.empty:
    print("Median interval (s):", round(float(intervals.median()), 6))
    print("Mean interval (s):", round(float(intervals.mean()), 6))
    print("CV:", round(float(intervals.std(ddof=0) / intervals.mean()), 6))
print("Saved evidence, timeline, and chart to:", OUT)
