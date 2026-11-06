from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np


PROJECTS = [
    "c-ares",
    "cjson",
    "dlt-daemon",
    "expat",
    "faad2",
    "isotp-c",
    "jansson",
    "json-c",
    "libmad",
    "libmspack",
    "libpcap",
    "libsndfile",
    "tinyxml2",
    "zlib",
]
DISPLAY_NAMES = {
    "cjson": "cJSON",
}
V0_COLOR = "#BFBFBF"
V1_COLOR = "#4F81BD"

# Fixed final 1,217-report counts, in PROJECTS order.
# Source: dedup_project_summary_14projects.csv (2026-10-27 frozen mapping).
EVALUABLE_COUNTS = np.array([103, 78, 92, 36, 151, 104, 128, 40, 112, 54, 115, 76, 63, 65])
RETAINED_COUNTS = np.array([27, 14, 35, 19, 46, 96, 68, 20, 27, 41, 25, 30, 49, 37])


def load_counts() -> tuple[np.ndarray, np.ndarray]:
    return EVALUABLE_COUNTS, RETAINED_COUNTS


def configure_style() -> None:
    plt.rcParams.update(
        {
            "font.family": "serif",
            "font.serif": ["Times New Roman", "DejaVu Serif", "STIXGeneral"],
            "mathtext.fontset": "stix",
            "axes.linewidth": 0.85,
            "axes.labelsize": 13.5,
            "xtick.labelsize": 12.5,
            "ytick.labelsize": 13,
            "legend.fontsize": 12.5,
            "xtick.direction": "in",
            "ytick.direction": "in",
            "xtick.major.width": 0.8,
            "ytick.major.width": 0.8,
            "grid.linewidth": 0.55,
            "grid.alpha": 0.28,
            "legend.frameon": False,
            "figure.facecolor": "white",
            "axes.facecolor": "white",
            "savefig.facecolor": "white",
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
        }
    )


def annotate_bars(ax: plt.Axes, bars, values) -> None:
    ax.bar_label(
        bars,
        labels=[str(int(value)) for value in values],
        padding=3,
        fontsize=12.5,
        color="#222222",
    )


def annotate_filtered_counts(ax: plt.Axes, y_positions, before, after) -> None:
    ax.text(
        1.04, 1.015, "Filtered", transform=ax.transAxes,
        ha="left", va="bottom", fontsize=12.5,
    )
    for ypos, baseline, retained in zip(y_positions, before, after):
        filtered = int(baseline - retained)
        ratio = filtered / baseline * 100.0 if baseline else 0.0
        ax.text(
            1.04,
            ypos,
            f"{filtered} ({ratio:.1f}%)",
            transform=ax.get_yaxis_transform(),
            ha="left",
            va="center",
            fontsize=12.5,
            color="#444444",
        )


def build_plot() -> tuple[plt.Figure, plt.Axes]:
    configure_style()

    raw_crashes, retained_crashes = load_counts()
    y = np.arange(len(PROJECTS))
    height = 0.34
    offset = 0.21

    fig, ax = plt.subplots(figsize=(6.9, 7.4), dpi=300)

    bars_before = ax.barh(
        y - offset,
        raw_crashes,
        height=height,
        color=V0_COLOR,
        edgecolor="#6E6E6E",
        linewidth=0.75,
        label="Before Filtering",
        zorder=3,
    )
    bars_after = ax.barh(
        y + offset,
        retained_crashes,
        height=height,
        color=V1_COLOR,
        edgecolor="#315A8A",
        linewidth=0.75,
        label="After Filtering",
        zorder=3,
    )

    annotate_bars(ax, bars_before, raw_crashes)
    annotate_bars(ax, bars_after, retained_crashes)
    annotate_filtered_counts(ax, y, raw_crashes, retained_crashes)

    ax.set_xlabel("Crash reports (n)")
    ax.set_yticks(y)
    ax.set_yticklabels([DISPLAY_NAMES.get(p, p) for p in PROJECTS])
    ax.set_ylim(len(PROJECTS) - 0.35, -0.65)
    ax.set_xlim(0, max(raw_crashes.max(), retained_crashes.max()) * 1.14)
    ax.tick_params(axis="y", length=0, pad=7)
    ax.grid(axis="x", linestyle="--", zorder=0)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.legend(
        loc="upper center",
        bbox_to_anchor=(0.5, 1.095),
        ncol=2,
        handlelength=1.4,
        columnspacing=1.2,
    )

    before_total = int(raw_crashes.sum())
    after_total = int(retained_crashes.sum())
    reduction = (before_total - after_total) / before_total * 100.0
    fig.text(
        0.5, 0.975,
        f"Total: {before_total:,} to {after_total:,} reports ({reduction:.2f}% filtered)",
        ha="center", va="top", fontsize=13,
    )
    fig.subplots_adjust(left=0.20, right=0.77, bottom=0.09, top=0.87)
    return fig, ax


def main() -> None:
    fig, _ = build_plot()
    out_dir = Path(__file__).resolve().parent
    fig.savefig(out_dir / "fig3.pdf", bbox_inches="tight")
    fig.savefig(out_dir / "fig3.png", dpi=300, bbox_inches="tight")
    plt.close(fig)


if __name__ == "__main__":
    main()
