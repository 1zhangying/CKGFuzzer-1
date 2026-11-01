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
V3_COLOR = "#4F81BD"

RETAINED_COUNTS = np.array([18, 11, 19, 30, 26, 14, 13, 13, 20, 30, 49, 15])
REPRESENTATIVE_COUNTS = np.array([5, 4, 3, 6, 6, 3, 2, 2, 5, 7, 11, 3])


def load_counts() -> tuple[np.ndarray, np.ndarray]:
    return RETAINED_COUNTS, REPRESENTATIVE_COUNTS


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


def annotate_saved_calls(ax: plt.Axes, x_positions, before, after) -> None:
    for xpos, baseline, selected in zip(x_positions, before, after):
        saved = int(baseline - selected)
        ratio = saved / baseline * 100.0 if baseline else 0.0
        top = max(baseline, selected)
        ax.text(
            xpos,
            top + 9.0,
            f"Saved {saved}\n({ratio:.1f}%)",
            ha="center",
            va="bottom",
            fontsize=9.0,
            color="#444444",
            linespacing=0.9,
        )


def build_plot() -> tuple[plt.Figure, plt.Axes]:
    configure_style()

    retained_counts, representative_counts = load_counts()
    x = np.arange(len(PROJECTS))
    width = 0.34

    fig, ax = plt.subplots(figsize=(10.8, 5.2), dpi=300)

    bars_before = ax.bar(
        x - width / 2,
        retained_counts,
        width=width,
        color=V0_COLOR,
        edgecolor="#6E6E6E",
        linewidth=0.75,
        label="Retained after Filtering",
        zorder=3,
    )
    bars_after = ax.bar(
        x + width / 2,
        representative_counts,
        width=width,
        color=V3_COLOR,
        edgecolor="#315A8A",
        linewidth=0.75,
        label="Representatives",
        zorder=3,
    )

    annotate_bars(ax, bars_before, retained_counts)
    annotate_bars(ax, bars_after, representative_counts)
    annotate_saved_calls(ax, x, retained_counts, representative_counts)

    ax.set_ylabel("Crash Reports")
    ax.set_xticks(x)
    ax.set_xticklabels([DISPLAY_NAMES.get(p, p) for p in PROJECTS], rotation=35, ha="right")
    ax.set_ylim(0, max(retained_counts.max(), representative_counts.max()) * 1.30)
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
    fig.savefig(out_dir / "fig4.pdf", bbox_inches="tight")
    fig.savefig(out_dir / "fig4.png", dpi=300, bbox_inches="tight")
    plt.close(fig)


if __name__ == "__main__":
    main()
