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
V3_COLOR = "#4F81BD"

# Fixed final 534-retained / 96-representative counts, in PROJECTS order.
# Source: dedup_project_summary_14projects.csv (2026-10-27 frozen mapping).
RETAINED_COUNTS = np.array([27, 14, 35, 19, 46, 96, 68, 20, 27, 41, 25, 30, 49, 37])
REPRESENTATIVE_COUNTS = np.array([8, 4, 5, 3, 9, 17, 12, 3, 4, 7, 4, 6, 7, 7])


def load_counts() -> tuple[np.ndarray, np.ndarray]:
    return RETAINED_COUNTS, REPRESENTATIVE_COUNTS


def configure_style() -> None:
    plt.rcParams.update(
        {
            "font.family": "serif",
            "font.serif": ["Times New Roman", "DejaVu Serif", "STIXGeneral"],
            "mathtext.fontset": "stix",
            "axes.linewidth": 0.85,
            "axes.labelsize": 11.5,
            "xtick.labelsize": 9.5,
            "ytick.labelsize": 10,
            "legend.fontsize": 10.5,
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
        padding=2,
        fontsize=9,
        color="#222222",
    )


def annotate_saved_calls(ax: plt.Axes, x_positions, before, after) -> None:
    ax.text(
        1.03, 1.015, "Saved calls", transform=ax.transAxes,
        ha="left", va="bottom", fontsize=10.5,
    )
    for xpos, baseline, selected in zip(x_positions, before, after):
        saved = int(baseline - selected)
        ratio = saved / baseline * 100.0 if baseline else 0.0
        ax.text(
            13.95,
            xpos,
            f"{saved} ({ratio:.1f}%)",
            transform=ax.transData,
            clip_on=False,
            ha="left",
            va="center",
            fontsize=9,
            color="#444444",
        )


def build_plot(
    counts: tuple[np.ndarray, np.ndarray] | None = None,
    representative_label: str = "Representatives",
) -> tuple[plt.Figure, plt.Axes]:
    configure_style()

    retained_counts, representative_counts = counts if counts is not None else load_counts()
    x = np.arange(len(PROJECTS))
    width = 0.34
    offset = 0.21

    fig, ax = plt.subplots(figsize=(6.9, 3.35), dpi=300)

    bars_before = ax.bar(
        x - offset,
        retained_counts,
        width=width,
        color=V0_COLOR,
        edgecolor="#6E6E6E",
        linewidth=0.75,
        label="Retained after Filtering",
        zorder=3,
    )
    bars_after = ax.bar(
        x + offset,
        representative_counts,
        width=width,
        color=V3_COLOR,
        edgecolor="#315A8A",
        linewidth=0.75,
        label=representative_label,
        zorder=3,
    )

    annotate_bars(ax, bars_before, retained_counts)
    annotate_bars(ax, bars_after, representative_counts)

    ax.set_ylabel("Crash reports (n)")
    ax.set_xticks(x)
    ax.set_xticklabels(
        [DISPLAY_NAMES.get(p, p) for p in PROJECTS],
        rotation=45,
        ha="right",
        rotation_mode="anchor",
    )
    ax.set_xlim(-0.75, len(PROJECTS) - 0.25)
    ax.set_ylim(0, max(retained_counts.max(), representative_counts.max()) * 1.16)
    ax.tick_params(axis="x", length=0, pad=3)
    ax.grid(axis="y", linestyle="--", zorder=0)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.legend(
        loc="upper right",
        bbox_to_anchor=(1.0, 1.005),
        ncol=2,
        handlelength=1.3,
        columnspacing=1.0,
        borderaxespad=0.0,
    )

    before_total = int(retained_counts.sum())
    after_total = int(representative_counts.sum())
    reduction = (before_total - after_total) / before_total * 100.0
    fig.text(
        0.5, 0.985,
        f"Total: {before_total:,} reports to {after_total:,} representatives ({reduction:.2f}% fewer)",
        ha="center", va="top", fontsize=11,
    )
    fig.subplots_adjust(left=0.085, right=0.985, bottom=0.235, top=0.885)
    return fig, ax


def main() -> None:
    fig, _ = build_plot()
    out_dir = Path(__file__).resolve().parent
    fig.savefig(out_dir / "fig4.pdf", bbox_inches="tight")
    fig.savefig(out_dir / "fig4.png", dpi=300, bbox_inches="tight")
    plt.close(fig)


if __name__ == "__main__":
    main()
