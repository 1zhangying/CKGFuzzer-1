from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np


PROJECTS = [
    "c-ares",
    "cjson",
    "expat",
    "faad2",
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

EVALUABLE_COUNTS = np.array([94, 75, 36, 135, 86, 34, 98, 26, 110, 76, 63, 43])
RETAINED_COUNTS = np.array([18, 11, 19, 30, 26, 14, 13, 13, 20, 30, 49, 15])


def load_counts() -> tuple[np.ndarray, np.ndarray]:
    return EVALUABLE_COUNTS, RETAINED_COUNTS


def configure_style() -> None:
    plt.rcParams.update(
        {
            "font.family": "serif",
            "font.serif": ["Times New Roman", "DejaVu Serif", "STIXGeneral"],
            "mathtext.fontset": "stix",
            "axes.linewidth": 0.85,
            "axes.labelsize": 12.5,
            "xtick.labelsize": 10.5,
            "ytick.labelsize": 10.5,
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
        }
    )


def annotate_bars(ax: plt.Axes, bars, values, dy: float = 0.75) -> None:
    for bar, value in zip(bars, values):
        ax.text(
            bar.get_x() + bar.get_width() / 2.0,
            bar.get_height() + dy,
            f"{int(value)}",
            ha="center",
            va="bottom",
            fontsize=9.5,
            color="#222222",
        )


def annotate_filtered_counts(ax: plt.Axes, x_positions, before, after) -> None:
    for xpos, baseline, retained in zip(x_positions, before, after):
        filtered = int(baseline - retained)
        ratio = filtered / baseline * 100.0 if baseline else 0.0
        top = max(baseline, retained)
        ax.text(
            xpos,
            top + 9.0,
            f"Filtered {filtered}\n({ratio:.1f}%)",
            ha="center",
            va="bottom",
            fontsize=9.0,
            color="#444444",
            linespacing=0.9,
        )


def build_plot() -> tuple[plt.Figure, plt.Axes]:
    configure_style()

    raw_crashes, retained_crashes = load_counts()
    x = np.arange(len(PROJECTS))
    width = 0.34

    fig, ax = plt.subplots(figsize=(10.8, 5.2), dpi=300)

    bars_before = ax.bar(
        x - width / 2,
        raw_crashes,
        width=width,
        color=V0_COLOR,
        edgecolor="#6E6E6E",
        linewidth=0.75,
        label="Before Filtering",
        zorder=3,
    )
    bars_after = ax.bar(
        x + width / 2,
        retained_crashes,
        width=width,
        color=V1_COLOR,
        edgecolor="#315A8A",
        linewidth=0.75,
        label="After Filtering",
        zorder=3,
    )

    annotate_bars(ax, bars_before, raw_crashes)
    annotate_bars(ax, bars_after, retained_crashes)
    annotate_filtered_counts(ax, x, raw_crashes, retained_crashes)

    ax.set_ylabel("Crash Reports")
    ax.set_xticks(x)
    ax.set_xticklabels([DISPLAY_NAMES.get(p, p) for p in PROJECTS], rotation=35, ha="right")
    ax.set_ylim(0, max(raw_crashes.max(), retained_crashes.max()) * 1.18)
    ax.grid(axis="y", linestyle="--", zorder=0)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.legend(
        loc="upper center",
        bbox_to_anchor=(0.5, 1.10),
        ncol=2,
        handlelength=1.4,
        columnspacing=1.6,
    )

    fig.tight_layout(rect=[0.0, 0.0, 1.0, 0.94])
    return fig, ax


def main() -> None:
    fig, _ = build_plot()
    out_dir = Path(__file__).resolve().parent
    fig.savefig(out_dir / "fig3.pdf", bbox_inches="tight")
    fig.savefig(out_dir / "fig3.png", dpi=300, bbox_inches="tight")
    plt.close(fig)


if __name__ == "__main__":
    main()
