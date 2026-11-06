from pathlib import Path
from collections import Counter
import pandas as pd

# =====================================
# 1. CONFIGURATION
# =====================================

ROOT = Path(__file__).resolve().parents[2]

INPUT = (
    ROOT / "data/raw/scenario-01-neris/"
    "labeled-flows/capture20110810.binetflow"
)

OUTPUT = ROOT / "reports/week1/generated"
OUTPUT.mkdir(parents=True, exist_ok=True)

INFECTED_IP = "147.32.84.165"
CHUNK_SIZE = 100000

FLOW_OUTPUT = OUTPUT / "neris_labeled_flows.csv"

COLUMNS = [
    "StartTime",
    "Dur",
    "Proto",
    "SrcAddr",
    "Sport",
    "Dir",
    "DstAddr",
    "Dport",
    "Label",
]

# =====================================
# 2. LABEL CLASSIFICATION
# =====================================

def classify_label(label):
    label = str(label).strip()

    categories = [
        "From-Botnet",
        "To-Botnet",
        "From-Normal",
        "To-Normal",
        "From-Background",
        "To-Background",
        "Background",
    ]

    for category in categories:
        if label == f"flow={category}" or label.startswith(
            f"flow={category}-"
        ):
            return category

    return "Other/Unknown"

# =====================================
# 3. PROCESS DATASET IN CHUNKS
# =====================================

label_counts = Counter()
category_counts = Counter()

total_flows = 0
infected_host_flows = 0
first_write = True

for chunk in pd.read_csv(
    INPUT,
    usecols=COLUMNS,
    dtype=str,
    chunksize=CHUNK_SIZE
):

    total_flows += len(chunk)

    chunk["Label"] = (
        chunk["Label"]
        .fillna("MISSING")
        .str.strip()
    )

    # Thống kê nhãn gốc
    label_counts.update(
        chunk["Label"].value_counts().to_dict()
    )

    # Phân nhóm nhãn
    chunk["label_category"] = (
        chunk["Label"].apply(classify_label)
    )

    category_counts.update(
        chunk["label_category"]
        .value_counts()
        .to_dict()
    )

    # Lọc flows có liên quan đến IP Neris
    mask = (
        (chunk["SrcAddr"] == INFECTED_IP) |
        (chunk["DstAddr"] == INFECTED_IP)
    )

    infected = chunk.loc[mask].copy()

    infected_host_flows += len(infected)

    # Xuất theo từng chunk để tránh tốn RAM
    if not infected.empty:
        infected.to_csv(
            FLOW_OUTPUT,
            mode="w" if first_write else "a",
            header=first_write,
            index=False
        )

        first_write = False


# =====================================
# 4. EXPORT LABEL DISTRIBUTION
# =====================================

label_df = pd.DataFrame(
    label_counts.items(),
    columns=["label", "count"]
).sort_values("count", ascending=False)

label_df.to_csv(
    OUTPUT / "label_distribution.csv",
    index=False
)

category_df = pd.DataFrame(
    category_counts.items(),
    columns=["category", "count"]
).sort_values("count", ascending=False)

category_df.to_csv(
    OUTPUT / "label_category_summary.csv",
    index=False
)


# =====================================
# 5. SUMMARY
# =====================================

print("\n===== DATASET SUMMARY =====")
print("Total labeled flows:", total_flows)
print("Flows involving Neris:", infected_host_flows)

print("\n===== LABEL CATEGORY SUMMARY =====")
print(category_df.to_string(index=False))

print("\n===== TOP 20 LABELS =====")
print(label_df.head(20).to_string(index=False))

print("\nOutputs saved to:", OUTPUT)
