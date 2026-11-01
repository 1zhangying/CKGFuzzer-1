import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

from crash.summarize_prompt_ablation import aggregate, read_csv


def write_csv(path: Path, rows: str) -> None:
    path.write_text(rows.strip() + "\n", encoding="utf-8")


class SummarizePromptAblationTest(unittest.TestCase):
    def test_aggregates_six_observations_and_checks_monotonicity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            per_run = root / "runs.csv"
            anchors = root / "anchors.csv"
            output = root / "output"
            header = (
                "Variant,Run,Population,TP,FP,TN,FN,"
                "Precision,Recall,F1\n"
            )
            rows = []
            values = {
                "P0": (0.70, 0.80, 0.75),
                "P1": (0.72, 0.82, 0.77),
                "P2": (0.74, 0.84, 0.79),
                "P3": (0.76, 0.86, 0.81),
            }
            for variant, (precision, recall, f1) in values.items():
                count = 5 if variant in {"P0", "P3"} else 6
                for index in range(count):
                    offset = (
                        (-0.01, 0.0, 0.01)[(index % 3) - 1]
                        if variant in {"P1", "P2"}
                        else 0.0
                    )
                    rows.append(
                        f"{variant},run{index + 1},all_1217,1,1,1,1,"
                        f"{precision + offset},{recall + offset},{f1 + offset}"
                    )
            write_csv(per_run, header + "\n".join(rows))
            write_csv(
                anchors,
                "Prompt,TP,FP,TN,FN,Precision,Recall,F1\n"
                "P0,1,1,1,1,0.70,0.80,0.75\n"
                "P3,1,1,1,1,0.76,0.86,0.81",
            )

            aggregate(
                Namespace(
                    per_run_metrics=per_run,
                    anchors=anchors,
                    output=output,
                    runs_per_variant=6,
                    main_selection="median_f1_run",
                    require_monotonic=True,
                )
            )

            main = read_csv(output / "prompt_ablation_main.csv")
            self.assertEqual([row["Prompt"] for row in main], ["P0", "P1", "P2", "P3"])
            self.assertEqual([row["Source"] for row in main], [
                "formal_anchor",
                "median_f1_run",
                "median_f1_run",
                "formal_anchor",
            ])
            self.assertAlmostEqual(float(main[0]["F1"]), 0.75)
            self.assertAlmostEqual(float(main[1]["F1"]), 0.77)
            self.assertAlmostEqual(float(main[2]["F1"]), 0.79)
            self.assertAlmostEqual(float(main[3]["F1"]), 0.81)


if __name__ == "__main__":
    unittest.main()
