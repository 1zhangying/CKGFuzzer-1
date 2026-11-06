import csv
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

from figure2 import PROJECTS, build_plot


PROJECT_SUMMARY = (
    Path(__file__).resolve().parents[3]
    / "fuzzing_llm_engine/results/rebucket_comparison_20261030/rebucket_project_summary.csv"
)


def load_rebucket_counts() -> tuple[np.ndarray, np.ndarray]:
    with PROJECT_SUMMARY.open(encoding="utf-8", newline="") as source:
        rows = {row["Project"]: row for row in csv.DictReader(source)}
    retained_counts = np.array([int(rows[project]["Samples"]) for project in PROJECTS])
    representative_counts = np.array([int(rows[project]["Clusters"]) for project in PROJECTS])
    return retained_counts, representative_counts


def main() -> None:
    fig, _ = build_plot(
        counts=load_rebucket_counts(),
        representative_label="ReBucket representatives",
    )
    out_dir = Path(__file__).resolve().parent
    fig.savefig(out_dir / "fig4_rebucket.pdf", bbox_inches="tight")
    fig.savefig(out_dir / "fig4_rebucket.png", dpi=300, bbox_inches="tight")
    plt.close(fig)


if __name__ == "__main__":
    main()
