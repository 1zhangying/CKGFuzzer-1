"""Redraw the CrashSage pipeline figure as a vector graphic at insertion width.

The previous canvas was 1,086 pt wide. At the 0.75 linewidth insertion width
used in the manuscript it is scaled to about 0.24x, and the 16 pt labels render
at roughly 3.8 pt. This script keeps the four stages, their order, and the step
chain inside each stage, and lays them out on a 259 pt wide page, which is the
insertion width, so the label sizes are the sizes that appear in print.

Run with the Python that has PyMuPDF available.
"""

from pathlib import Path

import pymupdf

PAGE_W = 259.0
MARGIN = 6.0
BOX_L = MARGIN
BOX_R = PAGE_W - MARGIN

TITLE_SIZE = 8.0
STEP_SIZE = 6.8
TITLE_TO_STEP = 10.5
STEP_GAP = 11.2
ARROW_GAP = 5.6
PAD_TOP = 11.0
PAD_BOTTOM = 7.0
STAGE_GAP = 12.0

# Step chains follow the order of the original pipeline figure.
STAGES = [
    (
        "Rule-Guided Crash Attribution",
        [
            "Raw sanitizer output",
            "Evidence normalization",
            "Rule matching on sanitizer signals and stack-frame roles",
            "Evidence items and evidence resolution",
            "Triage labels",
            "Filtered normalized crash records",
        ],
    ),
    (
        "Representative Selection",
        [
            "Signature construction",
            "Exact signature and stack signature",
            "Signature verification",
            "Representative crash reports",
            "Seed location",
        ],
    ),
    (
        "Crash-Context Reconstruction",
        [
            "Seed replay",
            "Replay consistency check",
            "Source localization: static context",
            "Runtime inspection: pointer and object state",
            "Reconstructed crash records",
        ],
    ),
    (
        "LLM Analysis",
        [
            "Evidence package: report, triage label, context",
            "Two-hypothesis comparison under the differential prompt",
            "Structured analysis",
        ],
    ),
]


def stage_height(n_steps: int) -> float:
    return (
        PAD_TOP
        + TITLE_TO_STEP
        + (n_steps - 1) * STEP_GAP
        + PAD_BOTTOM
    )


def draw_down_arrow(page: pymupdf.Page, x: float, y_top: float, y_bottom: float) -> None:
    page.draw_line((x, y_top), (x, y_bottom - 2.2), color=(0.4, 0.4, 0.4), width=0.6)
    page.draw_polyline(
        [(x - 1.6, y_bottom - 2.8), (x + 1.6, y_bottom - 2.8), (x, y_bottom)],
        color=(0.4, 0.4, 0.4),
        fill=(0.4, 0.4, 0.4),
        width=0.3,
    )


def build() -> pymupdf.Document:
    total = sum(stage_height(len(steps)) for _, steps in STAGES)
    total += STAGE_GAP * (len(STAGES) - 1) + MARGIN * 2

    doc = pymupdf.open()
    page = doc.new_page(width=PAGE_W, height=total)

    y = MARGIN
    for index, (title, steps) in enumerate(STAGES):
        height = stage_height(len(steps))
        page.draw_rect(
            pymupdf.Rect(BOX_L, y, BOX_R, y + height),
            color=(0, 0, 0),
            width=0.8,
            radius=0.12,
        )

        title_y = y + PAD_TOP
        page.insert_text(
            (BOX_L + 7, title_y),
            f"({index + 1}) {title}",
            fontsize=TITLE_SIZE,
            fontname="hebo",
            color=(0, 0, 0),
        )

        for step_index, step in enumerate(steps):
            step_y = title_y + TITLE_TO_STEP + step_index * STEP_GAP
            page.insert_text(
                (BOX_L + 15, step_y),
                step,
                fontsize=STEP_SIZE,
                fontname="helv",
                color=(0, 0, 0),
            )
            if step_index < len(steps) - 1:
                draw_down_arrow(
                    page,
                    BOX_L + 9.2,
                    step_y + 2.4,
                    step_y + ARROW_GAP + 3.0,
                )

        y += height
        if index < len(STAGES) - 1:
            mid = PAGE_W / 2.0
            page.draw_line((mid, y + 1.5), (mid, y + STAGE_GAP - 3.6), color=(0, 0, 0), width=0.9)
            page.draw_polyline(
                [(mid - 2.8, y + STAGE_GAP - 4.2), (mid + 2.8, y + STAGE_GAP - 4.2), (mid, y + STAGE_GAP - 1.5)],
                color=(0, 0, 0),
                fill=(0, 0, 0),
                width=0.3,
            )
            y += STAGE_GAP

    return doc


def main() -> None:
    out_dir = Path(__file__).resolve().parent
    doc = build()
    doc.save(out_dir / "fig2.pdf", deflate=True, garbage=4)
    doc.close()
    print("wrote", out_dir / "fig2.pdf")


if __name__ == "__main__":
    main()
