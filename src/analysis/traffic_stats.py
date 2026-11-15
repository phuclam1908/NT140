from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt

# ==============================
# 1. CONFIGURATION
# ==============================

ROOT = Path(__file__).resolve().parents[2]

INPUT = ROOT / "data/processed/scenario-01-neris/zeek/conn.log"
OUTPUT = ROOT / "reports/week1/generated"

INFECTED_IP = "147.32.84.165"

OUTPUT.mkdir(parents=True, exist_ok=True)


# ==============================
# 2. LOAD DATA
# ==============================

df = pd.read_json(INPUT, lines=True)

traffic = df[
    df["id.orig_h"] == INFECTED_IP
].copy()

numeric_columns = [
    "duration",
    "orig_bytes",
    "resp_bytes",
    "orig_ip_bytes",
    "resp_ip_bytes"
]

for col in numeric_columns:
    if col in traffic.columns:
        traffic[col] = pd.to_numeric(
            traffic[col],
            errors="coerce"
        )


# ==============================
# 3. BASIC STATISTICS
# ==============================

print("===== CONNECTION STATISTICS =====")

print("Total Zeek connections:", len(df))
print("Connections originated by Neris:", len(traffic))
print("Unique destination IPs:", traffic["id.resp_h"].nunique())


# ==============================
# 4. PROTOCOL DISTRIBUTION
# ==============================

protocol_stats = (
    traffic["proto"]
    .value_counts()
    .rename_axis("protocol")
    .reset_index(name="connections")
)

print("\n===== PROTOCOL DISTRIBUTION =====")
print(protocol_stats.to_string(index=False))

protocol_stats.to_csv(
    OUTPUT / "protocol_distribution.csv",
    index=False
)


# ==============================
# 5. DESTINATION IP STATISTICS
# ==============================

destination_stats = (
    traffic["id.resp_h"]
    .value_counts()
    .rename_axis("destination_ip")
    .reset_index(name="connections")
)

print("\n===== TOP 10 DESTINATIONS =====")
print(destination_stats.head(10).to_string(index=False))

destination_stats.to_csv(
    OUTPUT / "destination_statistics.csv",
    index=False
)


# ==============================
# 6. PORT STATISTICS
# ==============================

port_stats = (
    traffic["id.resp_p"]
    .value_counts()
    .rename_axis("destination_port")
    .reset_index(name="connections")
)

print("\n===== TOP 10 PORTS =====")
print(port_stats.head(10).to_string(index=False))

port_stats.to_csv(
    OUTPUT / "port_distribution.csv",
    index=False
)


# ==============================
# 7. FLOW STATISTICS
# ==============================

flow_stats = (
    traffic.groupby(
        ["id.resp_h", "id.resp_p", "proto"],
        dropna=False
    )
    .agg(
        connection_count=("uid", "count"),

        avg_duration=("duration", "mean"),

        total_orig_bytes=(
            "orig_bytes",
            lambda x: x.sum(min_count=1)
        ),

        total_resp_bytes=(
            "resp_bytes",
            lambda x: x.sum(min_count=1)
        ),

        orig_bytes_observed=("orig_bytes", "count"),

        resp_bytes_observed=("resp_bytes", "count"),

        total_orig_ip_bytes=(
            "orig_ip_bytes",
            lambda x: x.sum(min_count=1)
        ),

        total_resp_ip_bytes=(
            "resp_ip_bytes",
            lambda x: x.sum(min_count=1)
        )
    )
    .reset_index()
    .sort_values(
        "connection_count",
        ascending=False
    )
)

flow_stats.to_csv(
    OUTPUT / "flow_statistics.csv",
    index=False
)

print("\n===== TOP 10 FLOW GROUPS =====")
print(flow_stats.head(10).to_string(index=False))


# ==============================
# 8. DATA QUALITY
# ==============================

missing_stats = traffic[numeric_columns].isna().sum()

print("\n===== MISSING VALUES =====")
print(missing_stats)

missing_stats.to_csv(
    OUTPUT / "missing_values.csv",
    header=["missing_count"]
)


# ==============================
# 9. CHART
# ==============================

top10 = destination_stats.head(10)

plt.figure(figsize=(12, 6))

plt.bar(
    top10["destination_ip"],
    top10["connections"]
)

plt.title("Top 10 Destination IPs - Neris")
plt.xlabel("Destination IP")
plt.ylabel("Connection Count")

plt.xticks(rotation=45, ha="right")
plt.tight_layout()

plt.savefig(
    OUTPUT / "top_destinations.png",
    dpi=150
)

plt.close()


# ==============================
# 10. FINISH
# ==============================

print("\nAnalysis completed!")
print("Results saved to:", OUTPUT)
