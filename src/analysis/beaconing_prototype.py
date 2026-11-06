from pathlib import Path
from datetime import datetime, timezone

import numpy as np
import pandas as pd


# ==================================
# 1. CONFIGURATION
# ==================================

ROOT = Path(__file__).resolve().parents[2]

INPUT = ROOT / "data/processed/scenario-01-neris/zeek/conn.log"

OUTPUT = ROOT / "reports/week1/generated"

INFECTED_IP = "147.32.84.165"

MIN_CONNECTIONS = 10
MIN_INTERVALS = 5

OUTPUT.mkdir(parents=True, exist_ok=True)


# ==================================
# 2. LOAD DATA
# ==================================

df = pd.read_json(INPUT, lines=True)

traffic = df[
    df["id.orig_h"] == INFECTED_IP
].copy()

traffic["ts"] = pd.to_numeric(
    traffic["ts"],
    errors="coerce"
)

traffic = traffic.dropna(
    subset=["ts", "id.resp_h", "id.resp_p", "proto"]
)


# ==================================
# 3. GROUP CONNECTIONS
# ==================================

group_columns = [
    "id.resp_h",
    "id.resp_p",
    "proto"
]

results = []

for keys, group in traffic.groupby(group_columns):

    dst_ip, dst_port, protocol = keys

    if len(group) < MIN_CONNECTIONS:
        continue

    # Sắp xếp thời điểm kết nối
    timestamps = np.sort(
        group["ts"].to_numpy(dtype=float)
    )

    # Tính khoảng cách giữa các lần kết nối
    intervals = np.diff(timestamps)

    # Ghi nhận timestamp trùng nhau
    zero_intervals = int(np.sum(intervals == 0))

    # Chỉ dùng khoảng cách dương để tính CV
    positive_intervals = intervals[intervals > 0]

    if len(positive_intervals) < MIN_INTERVALS:
        continue

    mean_interval = float(np.mean(positive_intervals))

    std_interval = float(
        np.std(positive_intervals, ddof=0)
    )

    cv = (
        std_interval / mean_interval
        if mean_interval > 0
        else np.nan
    )

    # Kiểm tra trạng thái kết nối
    states = group["conn_state"].value_counts()

    dominant_state = (
        states.index[0]
        if not states.empty
        else "unknown"
    )

    # Kiểm tra có gói phản hồi hay không
    resp_pkts = pd.to_numeric(
        group["resp_pkts"],
        errors="coerce"
    ).fillna(0)

    response_ratio = float(
        (resp_pkts > 0).mean()
    )

    # Chuẩn hóa timestamp về UTC
    first_seen = datetime.fromtimestamp(
        float(timestamps[0]),
        tz=timezone.utc
    ).isoformat()

    last_seen = datetime.fromtimestamp(
        float(timestamps[-1]),
        tz=timezone.utc
    ).isoformat()

    results.append({
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": protocol,

        "connection_count": len(group),
        "valid_intervals": len(positive_intervals),
        "duplicate_timestamps": zero_intervals,

        "mean_interval_s": mean_interval,
        "std_interval_s": std_interval,
        "median_interval_s": float(
            np.median(positive_intervals)
        ),
        "cv": cv,

        "dominant_conn_state": dominant_state,
        "response_ratio": response_ratio,

        "first_seen_utc": first_seen,
        "last_seen_utc": last_seen
    })


# ==================================
# 4. SORT RESULTS
# ==================================

result_df = pd.DataFrame(results)

if not result_df.empty:

    result_df = result_df.sort_values(
        ["cv", "connection_count"],
        ascending=[True, False]
    )

    print("\n===== BEACONING CANDIDATES =====")

    columns = [
        "dst_ip",
        "dst_port",
        "protocol",
        "connection_count",
        "mean_interval_s",
        "std_interval_s",
        "cv",
        "dominant_conn_state",
        "response_ratio"
    ]

    print(
        result_df[columns]
        .head(20)
        .to_string(index=False)
    )

else:
    print("No groups meet minimum requirements.")


# ==================================
# 5. EXPORT
# ==================================

output_file = OUTPUT / "beaconing_results.csv"

result_df.to_csv(output_file, index=False)

print("\nSaved:", output_file)
