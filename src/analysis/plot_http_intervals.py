from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[2]

INPUT = ROOT / "reports/week1/generated/http_post_timeline.csv"
OUTPUT = ROOT / "reports/week1/generated/http_post_intervals.png"

df = pd.read_csv(INPUT)

intervals = df["interval_s"].dropna().reset_index(drop=True)

plt.figure(figsize=(12, 5))

plt.plot(
    range(1, len(intervals) + 1),
    intervals,
    marker="o",
    markersize=4
)

plt.axhline(
    y=120,
    color="red",
    linestyle="--",
    label="120 seconds reference"
)

plt.axhline(
    y=intervals.median(),
    color="green",
    linestyle="--",
    label=f"Median: {intervals.median():.2f}s"
)

plt.title("Neris HTTP POST Inter-arrival Times")
plt.xlabel("POST Interval Number")
plt.ylabel("Inter-arrival Time (seconds)")

plt.legend()
plt.grid(alpha=0.3)
plt.tight_layout()

plt.savefig(OUTPUT, dpi=150)
plt.close()

print("Saved:", OUTPUT)

