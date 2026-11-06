from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]

ZEEK_PATH = (
    ROOT / "data/processed/scenario-01-neris/zeek/conn.log"
)

FLOW_PATH = (
    ROOT / "reports/week1/generated/neris_labeled_flows.csv"
)

INFECTED_IP = "147.32.84.165"

# 1. Load data
zeek = pd.read_json(ZEEK_PATH, lines=True)
flows = pd.read_csv(FLOW_PATH, low_memory=False)

# 2. Zeek timestamp -> UTC
zeek["time_utc"] = pd.to_datetime(
    zeek["ts"],
    unit="s",
    utc=True
)

# 3. CTU-13 timestamp
flows["time_local"] = pd.to_datetime(
    flows["StartTime"],
    format="%Y/%m/%d %H:%M:%S.%f",
    errors="coerce"
)

# Thử giả thuyết StartTime sử dụng giờ Prague
flows["time_utc"] = (
    flows["time_local"]
    .dt.tz_localize("Europe/Prague")
    .dt.tz_convert("UTC")
)

# 4. Chỉ lấy From-Botnet
botnet = flows[
    flows["Label"].str.startswith(
        "flow=From-Botnet",
        na=False
    )
].copy()

# 5. Chỉ lấy connections do Neris khởi tạo
zeek_botnet = zeek[
    zeek["id.orig_h"] == INFECTED_IP
].copy()

print("===== TIME ALIGNMENT =====")

print("\nZeek:")
print("First:", zeek_botnet["time_utc"].min())
print("Last :", zeek_botnet["time_utc"].max())

print("\nCTU-13 From-Botnet:")
print("First:", botnet["time_utc"].min())
print("Last :", botnet["time_utc"].max())

print("\n===== RECORD COUNTS =====")
print("Zeek:", len(zeek_botnet))
print("From-Botnet:", len(botnet))

# 6. Kiểm tra một endpoint cụ thể
target_ip = "31.192.109.167"

zeek_target = zeek_botnet[
    (zeek_botnet["id.resp_h"] == target_ip) &
    (zeek_botnet["id.resp_p"] == 80)
].copy()

flow_target = botnet[
    (botnet["SrcAddr"] == INFECTED_IP) &
    (botnet["DstAddr"] == target_ip) &
    (
        pd.to_numeric(
            botnet["Dport"],
            errors="coerce"
        ) == 80
    )
].copy()

print("\n===== HTTP C2 CANDIDATE =====")

print("Zeek connections:", len(zeek_target))
print("Labeled flows:", len(flow_target))

print("\nFirst 5 Zeek connections:")
print(
    zeek_target[
        ["time_utc", "id.orig_p", "id.resp_p", "uid"]
    ]
    .sort_values("time_utc")
    .head(5)
    .to_string(index=False)
)

print("\nFirst 5 labeled flows:")
print(
    flow_target[
        [
            "time_utc", "Sport",
            "Dport", "Dur", "Label"
        ]
    ]
    .sort_values("time_utc")
    .head(5)
    .to_string(index=False)
)
