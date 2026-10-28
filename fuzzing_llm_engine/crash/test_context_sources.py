"""Tests for crash-specific evidence source selection."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from crash.context_sources import filter_api_names, find_driver_source


class ContextSourceSelectionTest(unittest.TestCase):
    def test_api_selection_follows_crash_time_driver(self) -> None:
        source = """
        json_t *root = json_loadb(data, size, 0, &error);
        """
        selected = filter_api_names(
            source,
            ["json_string", "json_loadb", "json_dumps"],
        )
        self.assertEqual(selected, ["json_loadb"])

    def test_cpp_method_api_is_matched_by_call_syntax(self) -> None:
        source = "doc.Parse(data, size);"
        selected = filter_api_names(
            source,
            ["XMLDocument::XMLDocument", "XMLDocument::Parse"],
        )
        self.assertEqual(selected, ["XMLDocument::Parse"])

    def test_first_target_api_survives_without_direct_driver_call(self) -> None:
        source = "set_nibble(index, value, destination, 10);"
        selected = filter_api_names(
            source,
            ["set_nibble", "copy_bits"],
            required_apis=["copy_bits"],
        )
        self.assertEqual(selected, ["set_nibble", "copy_bits"])

    def test_per_crash_driver_precedes_shared_driver(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            crash_dir = root / "p1" / "crash" / "driver_1"
            shared_dir = root / "p1" / "fuzz_driver"
            crash_dir.mkdir(parents=True)
            shared_dir.mkdir(parents=True)
            crash_source = crash_dir / "driver_1_crash_2.cc"
            shared_source = shared_dir / "driver_1.cc"
            crash_source.write_text("crash-time source", encoding="utf-8")
            shared_source.write_text("shared source", encoding="utf-8")

            selected = find_driver_source(
                root,
                "p1",
                "driver_1",
                {"fuzz_driver_file": crash_source.name},
            )

        self.assertEqual(selected, str(crash_source))

    def test_shared_driver_remains_a_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shared_source = root / "p1" / "fuzz_driver" / "driver_1.cc"
            shared_source.parent.mkdir(parents=True)
            shared_source.write_text("shared source", encoding="utf-8")

            selected = find_driver_source(
                root,
                "p1",
                "driver_1",
                {"fuzz_driver_file": "missing.cc"},
            )

        self.assertEqual(selected, str(shared_source))


if __name__ == "__main__":
    unittest.main()
