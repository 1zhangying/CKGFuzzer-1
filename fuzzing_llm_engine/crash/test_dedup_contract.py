#!/usr/bin/env python3
"""Contract tests for the paper-aligned deduplication implementation."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest

import yaml


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crash.dedup import CrashRecord, DEDUP_SCHEMA_VERSION, DeduplicationEngine
from crash.triage import (
    compute_replay_key,
    compute_signatures,
    replay_keys_compatible,
)


def _parsed(
    func: str = "target_fn",
    location: str = "/src/target/a.c:10",
    bug_type: str = "heap-buffer-overflow",
):
    return {
        "bug_type": bug_type,
        "first_in_project_function": func,
        "first_in_project_frame": location,
    }


def _triage(exact: str, stack: str, fuzzy: str = "fuzzy:shared"):
    return {
        "signature": exact,
        "signature_source": "test",
        "stack_signature": stack,
        "fuzzy_signature": fuzzy,
    }


class DedupContractTests(unittest.TestCase):
    def test_exact_groups_are_bounded_and_map_to_direct_leaders(self):
        engine = DeduplicationEngine()
        triage = _triage("dedup:same-token", "stack:member-specific")

        results = [
            engine.add_crash(f"crash-{index}", triage, _parsed())
            for index in range(11)
        ]

        self.assertFalse(results[0]["is_duplicate"])
        for result in results[1:7]:
            self.assertTrue(result["is_duplicate"])
            self.assertEqual(result["duplicate_of"], "crash-0")
            self.assertEqual(result["match_level"], "exact")
        self.assertFalse(results[7]["is_duplicate"])
        self.assertEqual(results[7]["representative"], "crash-7")
        for result in results[8:]:
            self.assertTrue(result["is_duplicate"])
            self.assertEqual(result["duplicate_of"], "crash-7")

        stats = engine.get_dedup_stats()
        self.assertEqual(stats["total_crashes"], 11)
        self.assertEqual(stats["unique_crashes"], 2)
        self.assertEqual([cluster["count"] for cluster in stats["clusters"]], [7, 4])
        self.assertEqual(engine.validate_state(), [])

    def test_stack_match_maps_every_member_to_cluster_leader(self):
        engine = DeduplicationEngine()
        stack = "stack:v2:same-path"
        first = engine.add_crash(
            "z-leader",
            _triage("exact:a", stack),
            _parsed(location="/src/target/a.c:1"),
        )
        second = engine.add_crash(
            "a-member",
            _triage("exact:b", stack),
            _parsed(location="/src/target/b.c:2"),
        )
        third = engine.add_crash(
            "m-member",
            _triage("exact:c", stack),
            _parsed(location="/src/target/c.c:3"),
        )

        self.assertFalse(first["is_duplicate"])
        self.assertEqual(second["duplicate_of"], "z-leader")
        self.assertEqual(second["match_level"], "stack")
        self.assertEqual(third["duplicate_of"], "z-leader")
        self.assertEqual(third["match_level"], "stack")
        self.assertEqual(engine.get_representatives(), ["z-leader"])

    def test_earlier_stack_leader_wins_over_later_exact_leader(self):
        engine = DeduplicationEngine()
        engine.add_crash(
            "earlier-stack-leader",
            _triage("exact:early", "stack:shared"),
            _parsed(),
        )
        engine.add_crash(
            "later-exact-leader",
            _triage("exact:late", "stack:other"),
            _parsed(),
        )

        result = engine.add_crash(
            "ambiguous",
            _triage("exact:late", "stack:shared"),
            _parsed(),
        )
        self.assertEqual(result["duplicate_of"], "earlier-stack-leader")
        self.assertEqual(result["match_level"], "stack")

    def test_fuzzy_match_never_deduplicates(self):
        engine = DeduplicationEngine()
        engine.add_crash(
            "first",
            _triage("exact:first", "stack:first", "fuzzy:same"),
            _parsed(),
        )
        result = engine.add_crash(
            "second",
            _triage("exact:second", "stack:second", "fuzzy:same"),
            _parsed(),
        )

        self.assertFalse(result["is_duplicate"])
        self.assertEqual(result["fuzzy_similar_to"], "first")
        self.assertEqual(len(engine.get_representatives()), 2)

    def test_scope_does_not_mutate_the_match_relation(self):
        engine = DeduplicationEngine()
        triage = _triage("dedup:same-token", "stack:first")
        first = engine.add_crash(
            "driver-a-crash",
            triage,
            _parsed(),
            scope="driver-a",
        )
        second = engine.add_crash(
            "driver-b-crash",
            triage,
            _parsed(),
            scope="driver-b",
        )

        self.assertFalse(first["is_duplicate"])
        self.assertTrue(second["is_duplicate"])
        self.assertEqual(second["duplicate_of"], "driver-a-crash")

    def test_cluster_ids_for_shared_prefixes_do_not_collide(self):
        engine = DeduplicationEngine()
        first = engine.add_crash(
            "malloc-crash",
            _triage("dedup:__interceptor_malloc--a", "stack:malloc"),
            _parsed(),
        )
        second = engine.add_crash(
            "strlen-crash",
            _triage("dedup:__interceptor_strlen--b", "stack:strlen"),
            _parsed(),
        )

        self.assertFalse(second["is_duplicate"])
        self.assertNotEqual(first["cluster_id"], second["cluster_id"])
        self.assertEqual(len(engine.get_representatives()), 2)
        self.assertEqual(engine.validate_state(), [])

    def test_persistence_round_trip_rebuilds_identical_state(self):
        engine = DeduplicationEngine()
        stack = "stack:v2:shared"
        engine.add_crash(
            "leader",
            _triage("exact:a", stack),
            _parsed(),
            timestamp="2026-01-01T00:00:00",
        )
        engine.add_crash(
            "member",
            _triage("exact:b", stack),
            _parsed(),
            timestamp="2026-01-01T00:00:01",
        )

        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "dedup.yaml")
            engine.save_to_file(path)
            loaded = DeduplicationEngine()
            self.assertTrue(loaded.load_from_file(path))

        self.assertEqual(loaded.get_total_crash_count(), 2)
        self.assertEqual(loaded.get_unique_crash_count(), 1)
        self.assertEqual(loaded.get_representatives(), ["leader"])
        self.assertEqual(loaded.validate_state(), [])

    def test_legacy_load_rebuilds_records_instead_of_stored_clusters(self):
        records = {
            "first": CrashRecord(
                crash_id="first",
                signature="dedup:same",
                stack_signature="legacy-stack",
                fuzzy_signature="fuzzy:one",
                bug_type="heap-buffer-overflow",
                crash_function="target_fn",
                crash_location="/src/target/a.c:1",
            ),
            "second": CrashRecord(
                crash_id="second",
                signature="dedup:same",
                stack_signature="legacy-stack",
                fuzzy_signature="fuzzy:one",
                bug_type="heap-buffer-overflow",
                crash_function="target_fn",
                crash_location="/src/target/a.c:1",
            ),
            "third": CrashRecord(
                crash_id="third",
                signature="",
                stack_signature="legacy-stack",
                fuzzy_signature="fuzzy:two",
                bug_type="heap-buffer-overflow",
                crash_function="target_fn",
                crash_location="/src/target/b.c:2",
            ),
        }
        legacy = {
            "records": {
                crash_id: record.__dict__
                for crash_id, record in records.items()
            },
            "clusters": {
                "colliding-id": {
                    "cluster_id": "colliding-id",
                    "representative": "second",
                    "members": ["second"],
                    "bug_type": "heap-buffer-overflow",
                    "crash_function": "target_fn",
                    "count": 1,
                }
            },
            "cluster_map": {crash_id: "colliding-id" for crash_id in records},
        }

        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "legacy.yaml")
            with open(path, "w", encoding="utf-8") as handle:
                yaml.safe_dump(legacy, handle)
            loaded = DeduplicationEngine()
            self.assertTrue(loaded.load_from_file(path))
            loaded.save_to_file(path)
            reloaded = DeduplicationEngine()
            self.assertTrue(reloaded.load_from_file(path))

        self.assertEqual(loaded.get_unique_crash_count(), 2)
        self.assertEqual(loaded.get_representatives(), ["first", "third"])
        self.assertEqual(loaded.get_cluster("second")["representative"], "first")
        self.assertEqual(loaded.validate_state(), [])
        self.assertEqual(reloaded.get_unique_crash_count(), 2)
        self.assertEqual(reloaded.validate_state(), [])

    def test_legacy_load_accepts_records_without_new_schema_fields(self):
        legacy = {
            "records": {
                "first": {
                    "crash_id": "first",
                    "signature": "dedup:same",
                    "stack_signature": "stack:legacy",
                    "fuzzy_signature": "fuzzy:one",
                    "bug_type": "heap-buffer-overflow",
                    "crash_function": "target_fn",
                    "crash_location": "/src/target/a.c:1",
                },
                "second": {
                    "crash_id": "second",
                    "signature": "dedup:same",
                    "stack_signature": "stack:legacy",
                    "fuzzy_signature": "fuzzy:one",
                    "bug_type": "heap-buffer-overflow",
                    "crash_function": "target_fn",
                    "crash_location": "/src/target/a.c:1",
                },
            },
        }

        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "legacy.yaml")
            with open(path, "w", encoding="utf-8") as handle:
                yaml.safe_dump(legacy, handle)
            loaded = DeduplicationEngine()
            self.assertTrue(loaded.load_from_file(path))

        self.assertEqual(loaded.get_unique_crash_count(), 1)
        self.assertEqual(loaded.get_cluster("second")["representative"], "first")

    def test_signature_builder_uses_ordered_non_runtime_frames(self):
        parsed = {
            "bug_type": "heap-buffer-overflow",
            "dedup_token": None,
            "first_in_project_frame": "/src/project/a.c:10",
            "first_in_project_function": "project_fn",
            "frames": [
                {"func": "__asan_memcpy", "file": "/src/llvm-project/runtime.c"},
                {"func": "project_fn", "file": "/src/project/a.c"},
                {"func": "LLVMFuzzerTestOneInput", "file": "/src/project/fuzz.cc"},
                {"func": "driver_helper", "file": "/src/project/fuzz.cc"},
                {"func": "main", "file": "/src/project/main.c"},
                {"func": "fuzzer::Fuzzer::Loop", "file": "/src/llvm-project/fuzzer.cc"},
            ],
        }
        exact, basis, stack, fuzzy = compute_signatures(parsed)

        self.assertTrue(exact.startswith("exact:"))
        self.assertEqual(basis, "normalized_crash_site")
        self.assertTrue(stack.startswith("stack:v2:"))
        self.assertTrue(fuzzy.startswith("fuzzy:"))
        self.assertEqual(DEDUP_SCHEMA_VERSION, 2)

    def test_replay_key_uses_bug_location_and_ordered_non_runtime_stack(self):
        parsed = {
            "bug_type": "heap-buffer-overflow",
            "first_in_project_frame": "/src/project/a.c:10",
            "frames": [
                {"func": "__asan_memcpy", "file": "/src/llvm-project/runtime.c"},
                {"func": "project_fn", "file": "/src/project/a.c"},
                {"func": "LLVMFuzzerTestOneInput", "file": "/src/project/fuzz.cc"},
            ],
        }
        key = compute_replay_key(parsed)

        self.assertEqual(key["bug_type"], "heap-buffer-overflow")
        self.assertEqual(key["location"], "/src/project/a.c:10")
        self.assertEqual(
            key["non_runtime_frames"],
            ["project_fn", "LLVMFuzzerTestOneInput"],
        )
        self.assertTrue(replay_keys_compatible(key, dict(key)))
        changed = dict(key)
        changed["non_runtime_frames"] = ["project_fn"]
        self.assertFalse(replay_keys_compatible(key, changed))


if __name__ == "__main__":
    unittest.main()
