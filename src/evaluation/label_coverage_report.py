from pathlib import Path
import pandas as pd

BASE = Path("reports/week2/quy")
SOURCE = BASE / "generated/label_audit_for_lam.csv"
OUTPUT = BASE / "generated/label_coverage_summary.csv"
REPORT = BASE / "label_coverage_report.md"

rules = ["t1571", "t1071_001", "t1105"]

df = pd.read_csv(SOURCE)

required = [
    "transaction_id", "label_family", "match_status", *rules
]

missing = set(required) - set(df.columns)
if missing:
    raise ValueError(f"Missing columns: {missing}")

if not df["transaction_id"].is_unique:
    raise ValueError("Duplicate HTTP transaction IDs detected")

for rule in rules:
    df[rule] = (
        pd.to_numeric(df[rule], errors="raise")
        .astype(int)
    )
    if not df[rule].isin([0, 1]).all():
        raise ValueError(f"Invalid binary flags: {rule}")

df["any_alert"] = df[rules].any(axis=1).astype(int)

cohorts = {
    "ALL_PROVISIONAL": df,
    "DIRECT_ONLY": df[
        df["match_status"] == "direct_unique_start"
    ],
}

rows = []

for cohort_name, cohort in cohorts.items():
    for family, group in cohort.groupby("label_family"):
        total = len(group)
        alerted = int(group["any_alert"].sum())

        rows.append({
            "cohort": cohort_name,
            "label_family": family,
            "total": total,
            "any_alert": alerted,
            "t1571": int(group["t1571"].sum()),
            "t1071_001": int(group["t1071_001"].sum()),
            "t1105": int(group["t1105"].sum()),
            "coverage_pct": round(100 * alerted / total, 2),
        })

summary = pd.DataFrame(rows)
summary = summary.sort_values(
    ["cohort", "label_family"]
)

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
summary.to_csv(OUTPUT, index=False)

print("\n=== LABEL-SPECIFIC ALERT COVERAGE ===")
print(summary.to_string(index=False))

print("\n=== ALIGNMENT GATES ===")
print(df["match_status"].value_counts().to_string())

print("\n=== ALERTED TRANSACTIONS ===")
print("Total:", int(df["any_alert"].sum()))
print(
    "Direct:",
    int(df.loc[
        df["match_status"] == "direct_unique_start",
        "any_alert"
    ].sum())
)
print(
    "Overlap:",
    int(df.loc[
        df["match_status"] == "overlap_association_only",
        "any_alert"
    ].sum())
)

lines = [
    "# NT140 Week 2 - Label Coverage Report",
    "",
    "## Scope",
    "",
    f"- HTTP transactions: {len(df)}",
    "- Dataset: CTU-13 Scenario 1 (Neris)",
    "- Evaluation unit: HTTP transaction",
    "- Labels: provisional CTU-13 Argus alignment",
    "",
    "## Label-specific alert coverage",
    "",
    "| Cohort | Label family | Total | Any alert | T1571 | T1071.001 | T1105 | Coverage (%) |",
    "|---|---|---:|---:|---:|---:|---:|---:|",
]

for row in summary.itertuples(index=False):
    lines.append(
        f"| {row.cohort} | {row.label_family} | "
        f"{row.total} | {row.any_alert} | "
        f"{row.t1571} | {row.t1071_001} | "
        f"{row.t1105} | {row.coverage_pct:.2f} |"
    )

lines.extend([
    "",
    "## Evaluation limitations",
    "",
    "- Coverage is descriptive, not Precision or FPR.",
    "- Overlap associations are excluded in DIRECT_ONLY.",
    "- From-Botnet does not imply every HTTP event is C2.",
    "- HTTP-Ad/WEB labels are not verified benign negatives.",
    "- Scenario 1 was used during rule development.",
    "- Independent benign and hold-out evaluations are pending.",
    "- TP/FP/TN/FN are intentionally not assigned.",
])

REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")

print(f"\nSaved CSV: {OUTPUT}")
print(f"Saved report: {REPORT}")
