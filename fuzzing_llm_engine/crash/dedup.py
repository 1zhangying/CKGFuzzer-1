"""Multi-level crash deduplication engine.

Supports three signature levels:
  Level 1 (exact):  libFuzzer DEDUP_TOKEN — function call chain
  Level 2 (stack):  bug_type + top-N project function names (SHA256)
  Level 3 (fuzzy):  bug_type + crash function name only

Provides:
  - Exact duplicate detection
  - Cluster management for similar crashes
  - Persistence via YAML crash database
"""
from __future__ import annotations

import hashlib
import os
from collections import defaultdict
from dataclasses import dataclass, asdict, field
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml
from loguru import logger


@dataclass
class CrashRecord:
    crash_id: str
    signature: str
    stack_signature: str
    fuzzy_signature: str
    bug_type: Optional[str]
    crash_function: Optional[str]
    crash_location: Optional[str]
    timestamp: Optional[str]


@dataclass
class CrashCluster:
    cluster_id: str
    representative: str          # crash_id of the representative
    members: List[str]           # all crash_ids in this cluster
    bug_type: Optional[str]
    crash_function: Optional[str]
    count: int


class DeduplicationEngine:
    """In-memory dedup engine with persistence."""

    def __init__(self):
        self._records: Dict[str, CrashRecord] = {}
        # Indexes: signature -> set of crash_ids
        self._exact_index: Dict[str, Set[str]] = defaultdict(set)
        self._stack_index: Dict[str, Set[str]] = defaultdict(set)
        self._fuzzy_index: Dict[str, Set[str]] = defaultdict(set)
        # Cluster management: crash_id -> cluster_id
        self._cluster_map: Dict[str, str] = {}
        self._clusters: Dict[str, CrashCluster] = {}

    def add_crash(self, crash_id: str, triage_result: Dict[str, Any],
                  parsed: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Add a crash and check for duplicates.

        Returns dict with:
          is_duplicate: bool
          duplicate_of: Optional[str] — crash_id of the first matching crash
          cluster_id: str — cluster this crash belongs to
          match_level: Optional[str] — "exact" | "stack" | "fuzzy" | None
        """
        sig = triage_result.get("signature", "")
        stack_sig = triage_result.get("stack_signature", "")
        fuzzy_sig = triage_result.get("fuzzy_signature", "")

        bug_type = None
        crash_func = None
        crash_loc = None
        timestamp = None
        if parsed:
            bug_type = parsed.get("bug_type")
            crash_func = parsed.get("first_in_project_function")
            crash_loc = parsed.get("first_in_project_frame")

        record = CrashRecord(
            crash_id=crash_id,
            signature=sig,
            stack_signature=stack_sig,
            fuzzy_signature=fuzzy_sig,
            bug_type=bug_type,
            crash_function=crash_func,
            crash_location=crash_loc,
            timestamp=timestamp,
        )
        self._records[crash_id] = record

        # Check for duplicates at each level
        duplicate_of = None
        match_level = None

        # Level 1: Exact signature
        existing = self._exact_index.get(sig, set())
        if existing:
            duplicate_of = next(iter(existing))
            match_level = "exact"

        # Level 2: Stack signature
        if not duplicate_of and stack_sig:
            existing = self._stack_index.get(stack_sig, set())
            if existing:
                duplicate_of = next(iter(existing))
                match_level = "stack"

        # Level 3: Fuzzy signature (only suggest, don't auto-merge)
        fuzzy_match = None
        if not duplicate_of and fuzzy_sig:
            existing = self._fuzzy_index.get(fuzzy_sig, set())
            if existing:
                fuzzy_match = next(iter(existing))

        # Update indexes
        self._exact_index[sig].add(crash_id)
        if stack_sig:
            self._stack_index[stack_sig].add(crash_id)
        if fuzzy_sig:
            self._fuzzy_index[fuzzy_sig].add(crash_id)

        # Cluster management
        if duplicate_of:
            cluster_id = self._cluster_map.get(duplicate_of)
            if cluster_id and cluster_id in self._clusters:
                cluster = self._clusters[cluster_id]
                cluster.members.append(crash_id)
                cluster.count += 1
                self._cluster_map[crash_id] = cluster_id
            else:
                cluster_id = f"cluster_{sig[:12]}"
                cluster = CrashCluster(
                    cluster_id=cluster_id,
                    representative=duplicate_of,
                    members=[duplicate_of, crash_id],
                    bug_type=bug_type,
                    crash_function=crash_func,
                    count=2,
                )
                self._clusters[cluster_id] = cluster
                self._cluster_map[duplicate_of] = cluster_id
                self._cluster_map[crash_id] = cluster_id
        else:
            cluster_id = f"cluster_{sig[:12]}"
            cluster = CrashCluster(
                cluster_id=cluster_id,
                representative=crash_id,
                members=[crash_id],
                bug_type=bug_type,
                crash_function=crash_func,
                count=1,
            )
            self._clusters[cluster_id] = cluster
            self._cluster_map[crash_id] = cluster_id

        return {
            "is_duplicate": duplicate_of is not None,
            "duplicate_of": duplicate_of,
            "match_level": match_level,
            "fuzzy_similar_to": fuzzy_match if not duplicate_of else None,
            "cluster_id": self._cluster_map[crash_id],
            "cluster_size": self._clusters[self._cluster_map[crash_id]].count,
        }

    def get_cluster(self, crash_id: str) -> Optional[Dict[str, Any]]:
        cid = self._cluster_map.get(crash_id)
        if cid and cid in self._clusters:
            return asdict(self._clusters[cid])
        return None

    def get_all_clusters(self) -> List[Dict[str, Any]]:
        return [asdict(c) for c in self._clusters.values()]

    def get_unique_crash_count(self) -> int:
        return len(self._clusters)

    def get_total_crash_count(self) -> int:
        return len(self._records)

    def get_dedup_stats(self) -> Dict[str, Any]:
        total = self.get_total_crash_count()
        unique = self.get_unique_crash_count()
        return {
            "total_crashes": total,
            "unique_crashes": unique,
            "duplicates_filtered": total - unique,
            "dedup_ratio": round(1 - unique / total, 3) if total > 0 else 0.0,
            "clusters": [
                {
                    "cluster_id": c.cluster_id,
                    "representative": c.representative,
                    "count": c.count,
                    "bug_type": c.bug_type,
                    "crash_function": c.crash_function,
                }
                for c in self._clusters.values()
            ],
        }

    # ------ Persistence ------

    def save_to_file(self, path: str):
        data = {
            "records": {k: asdict(v) for k, v in self._records.items()},
            "clusters": {k: asdict(v) for k, v in self._clusters.items()},
            "cluster_map": self._cluster_map,
        }
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as f:
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True)

    def load_from_file(self, path: str) -> bool:
        if not os.path.isfile(path):
            return False
        try:
            with open(path, "r") as f:
                data = yaml.safe_load(f)
            if not data:
                return False

            for cid, rd in (data.get("records") or {}).items():
                rec = CrashRecord(**rd)
                self._records[cid] = rec
                self._exact_index[rec.signature].add(cid)
                if rec.stack_signature:
                    self._stack_index[rec.stack_signature].add(cid)
                if rec.fuzzy_signature:
                    self._fuzzy_index[rec.fuzzy_signature].add(cid)

            self._cluster_map = data.get("cluster_map") or {}
            for cid, cd in (data.get("clusters") or {}).items():
                self._clusters[cid] = CrashCluster(**cd)

            logger.info(f"Loaded dedup DB: {len(self._records)} records, "
                        f"{len(self._clusters)} clusters")
            return True
        except Exception as e:
            logger.error(f"Failed to load dedup DB from {path}: {e}")
            return False
