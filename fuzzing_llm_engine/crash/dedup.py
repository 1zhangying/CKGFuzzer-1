"""Paper-aligned multi-level crash deduplication.

The matching relation follows the representative-selection definition used by
CrashSage:

* exact matching uses the sanitizer dedup token, or the normalized crash-site
  fields when the token is unavailable;
* stack matching uses the bug type and a bounded, ordered non-runtime stack
  prefix;
* exact matching is checked before stack matching for an individual leader;
* leaders are considered in discovery order and a duplicate is mapped directly
  to its leader;
* fuzzy signatures are advisory only and never create a duplicate.

The implementation intentionally does not cap cluster size or compute a
transitive closure. Both would change the paper's matching method.
"""
from __future__ import annotations

import hashlib
import os
from collections import OrderedDict
from dataclasses import asdict, dataclass
from threading import RLock
from typing import Any, Dict, List, Optional, Tuple

import yaml
from loguru import logger


DEDUP_SCHEMA_VERSION = 2


@dataclass
class CrashRecord:
    crash_id: str
    signature: str
    stack_signature: str
    fuzzy_signature: str
    bug_type: Optional[str]
    crash_function: Optional[str]
    crash_location: Optional[str]
    timestamp: Optional[str] = None
    discovery_index: int = 0
    exact_basis: str = ""


@dataclass
class CrashCluster:
    cluster_id: str
    representative: str
    members: List[str]
    bug_type: Optional[str]
    crash_function: Optional[str]
    count: int


class DeduplicationEngine:
    """In-memory greedy leader clustering with persistence."""

    MAX_ANALYSIS_GROUP_SIZE = 7

    def __init__(self, max_analysis_group_size: int = MAX_ANALYSIS_GROUP_SIZE):
        if max_analysis_group_size < 1:
            raise ValueError("max_analysis_group_size must be positive")
        self._max_analysis_group_size = max_analysis_group_size
        self._lock = RLock()
        self._records: Dict[str, CrashRecord] = OrderedDict()
        # Matching indexes point only to representatives.
        self._exact_index: Dict[str, str] = {}
        self._stack_index: Dict[str, str] = {}
        # Fuzzy similarity is retained for diagnostics, never for merging.
        self._fuzzy_index: Dict[str, str] = {}
        self._cluster_map: Dict[str, str] = {}
        self._clusters: Dict[str, CrashCluster] = OrderedDict()
        self._representatives: List[str] = []
        self._representative_rank: Dict[str, int] = {}
        self._match_levels: Dict[str, str] = {}
        self._next_discovery_index = 0

    def add_crash(
        self,
        crash_id: str,
        triage_result: Dict[str, Any],
        parsed: Optional[Dict[str, Any]] = None,
        scope: Optional[str] = None,
        *,
        timestamp: Optional[str] = None,
        discovery_index: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Add a crash and map it to the first matching leader.

        ``scope`` is accepted for backward compatibility with existing callers
        but is deliberately ignored. Driver identity is already represented by
        the non-runtime stack prefix, and the paper's match relation does not
        include an additional driver scope.
        """
        del scope

        with self._lock:
            if crash_id in self._records:
                return self._existing_result(crash_id)

            parsed = parsed or {}
            index = (
                int(discovery_index)
                if discovery_index is not None
                else self._next_discovery_index
            )
            self._next_discovery_index = max(self._next_discovery_index, index + 1)

            signature = str(triage_result.get("signature") or "").strip()
            stack_signature = str(
                triage_result.get("stack_signature") or ""
            ).strip()
            fuzzy_signature = str(
                triage_result.get("fuzzy_signature") or ""
            ).strip()

            record = CrashRecord(
                crash_id=crash_id,
                signature=signature,
                stack_signature=stack_signature,
                fuzzy_signature=fuzzy_signature,
                bug_type=parsed.get("bug_type"),
                crash_function=parsed.get("first_in_project_function"),
                crash_location=parsed.get("first_in_project_frame"),
                timestamp=timestamp,
                discovery_index=index,
                exact_basis=str(triage_result.get("signature_source") or ""),
            )
            return self._place_record(record)

    def _existing_result(self, crash_id: str) -> Dict[str, Any]:
        cluster_id = self._cluster_map[crash_id]
        cluster = self._clusters[cluster_id]
        is_duplicate = cluster.representative != crash_id
        return {
            "is_duplicate": is_duplicate,
            "duplicate_of": cluster.representative if is_duplicate else None,
            "representative": cluster.representative,
            "match_level": self._match_levels.get(crash_id),
            "exact_basis": self._records[crash_id].exact_basis,
            "fuzzy_similar_to": None,
            "cluster_id": cluster_id,
            "cluster_size": cluster.count,
        }

    def _place_record(
        self,
        record: CrashRecord,
        *,
        stack_key_override: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Insert one record in discovery order.

        ``stack_key_override`` is used only while loading legacy databases whose
        old project-only stack keys are not equivalent to the current paper
        implementation. Passing ``""`` disables legacy stack matching without
        discarding the stored value.
        """
        self._records[record.crash_id] = record

        stack_key = (
            record.stack_signature
            if stack_key_override is None
            else stack_key_override
        )
        matched = self._first_matching_representative(
            record.signature,
            stack_key,
        )
        fuzzy_rep = (
            self._fuzzy_index.get(record.fuzzy_signature)
            if record.fuzzy_signature and not matched
            else None
        )

        if matched is not None:
            representative, match_level = matched
            cluster_id = self._cluster_map[representative]
            cluster = self._clusters[cluster_id]
            cluster.members.append(record.crash_id)
            cluster.count = len(cluster.members)
            self._cluster_map[record.crash_id] = cluster_id
            self._match_levels[record.crash_id] = match_level
        else:
            representative = record.crash_id
            cluster_id = self._new_cluster_id(record)
            cluster = CrashCluster(
                cluster_id=cluster_id,
                representative=record.crash_id,
                members=[record.crash_id],
                bug_type=record.bug_type,
                crash_function=record.crash_function,
                count=1,
            )
            self._clusters[cluster_id] = cluster
            self._cluster_map[record.crash_id] = cluster_id
            self._representative_rank[record.crash_id] = len(
                self._representatives
            )
            self._representatives.append(record.crash_id)
            if record.signature:
                self._exact_index[record.signature] = record.crash_id
            if stack_key:
                self._stack_index[stack_key] = record.crash_id
            if record.fuzzy_signature:
                self._fuzzy_index.setdefault(
                    record.fuzzy_signature,
                    record.crash_id,
                )

        return {
            "is_duplicate": matched is not None,
            "duplicate_of": representative if matched is not None else None,
            "representative": representative,
            "match_level": matched[1] if matched is not None else None,
            "exact_basis": record.exact_basis,
            "fuzzy_similar_to": fuzzy_rep,
            "cluster_id": cluster_id,
            "cluster_size": cluster.count,
        }

    def _first_matching_representative(
        self,
        exact_signature: str,
        stack_signature: str,
    ) -> Optional[Tuple[str, str]]:
        """Return the earliest leader matching exact or stack.

        This mirrors the paper algorithm: leaders are traversed in discovery
        order, and exact is only preferred over stack when both match the same
        leader.
        """
        candidates: List[Tuple[int, int, str, str]] = []

        if exact_signature:
            representative = self._exact_index.get(exact_signature)
            if representative is not None and self._has_group_capacity(representative):
                candidates.append(
                    (
                        self._representative_rank[representative],
                        0,
                        representative,
                        "exact",
                    )
                )

        if stack_signature:
            representative = self._stack_index.get(stack_signature)
            if representative is not None and self._has_group_capacity(representative):
                candidates.append(
                    (
                        self._representative_rank[representative],
                        1,
                        representative,
                        "stack",
                    )
                )

        if not candidates:
            return None
        _, _, representative, match_level = min(candidates)
        return representative, match_level

    def _has_group_capacity(self, representative: str) -> bool:
        """Keep one leader error from propagating through an unbounded group."""
        cluster_id = self._cluster_map.get(representative)
        if not cluster_id or cluster_id not in self._clusters:
            return False
        return (
            self._clusters[cluster_id].count
            < self._max_analysis_group_size
        )

    @staticmethod
    def _new_cluster_id(record: CrashRecord) -> str:
        """Build a collision-resistant, reproducible cluster identifier.

        Hashing the complete canonical key before formatting avoids the former
        collision where structured prefixes such as ``dedup:__interceptor``
        were truncated before the non-deterministic hash suffix.
        """
        if record.signature:
            key = f"exact:{record.signature}"
        elif record.stack_signature:
            key = f"stack:{record.stack_signature}"
        else:
            key = f"crash:{record.crash_id}"
        # The leader identity is part of the cluster identity. This guarantees
        # uniqueness even during conservative legacy migration, where two old
        # records may deliberately share a matching key without being merged.
        digest = hashlib.sha256(
            f"leader:{record.crash_id}|{key}".encode("utf-8")
        ).hexdigest()
        return f"cluster_{digest}"

    def get_cluster(self, crash_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            cluster_id = self._cluster_map.get(crash_id)
            if cluster_id and cluster_id in self._clusters:
                return asdict(self._clusters[cluster_id])
            return None

    def get_representatives(self) -> List[str]:
        with self._lock:
            return list(self._representatives)

    def get_all_clusters(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [
                asdict(self._clusters[self._cluster_map[crash_id]])
                for crash_id in self._representatives
            ]

    def get_unique_crash_count(self) -> int:
        with self._lock:
            return len(self._clusters)

    def get_total_crash_count(self) -> int:
        with self._lock:
            return len(self._records)

    def get_dedup_stats(self) -> Dict[str, Any]:
        with self._lock:
            total = len(self._records)
            unique = len(self._clusters)
            clusters = [
                {
                    "cluster_id": self._clusters[
                        self._cluster_map[crash_id]
                    ].cluster_id,
                    "representative": self._clusters[
                        self._cluster_map[crash_id]
                    ].representative,
                    "count": self._clusters[
                        self._cluster_map[crash_id]
                    ].count,
                    "bug_type": self._clusters[
                        self._cluster_map[crash_id]
                    ].bug_type,
                    "crash_function": self._clusters[
                        self._cluster_map[crash_id]
                    ].crash_function,
                }
                for crash_id in self._representatives
            ]
            return {
                "total_crashes": total,
                "unique_crashes": unique,
                "duplicates_filtered": total - unique,
                "dedup_ratio": round(1 - unique / total, 3) if total else 0.0,
                "clusters": clusters,
            }

    def validate_state(self) -> List[str]:
        """Return invariant violations without mutating the database."""
        with self._lock:
            issues: List[str] = []
            active_members: Dict[str, str] = {}

            if len(self._representatives) != len(set(self._representatives)):
                issues.append("representative order contains duplicates")

            for cluster_id, cluster in self._clusters.items():
                if cluster.count != len(cluster.members):
                    issues.append(
                        f"{cluster_id}: count={cluster.count} "
                        f"members={len(cluster.members)}"
                    )
                if cluster.representative not in cluster.members:
                    issues.append(
                        f"{cluster_id}: representative is not a member"
                    )
                if len(cluster.members) != len(set(cluster.members)):
                    issues.append(f"{cluster_id}: duplicate members")
                if cluster.count > self._max_analysis_group_size:
                    issues.append(
                        f"{cluster_id}: count exceeds "
                        f"{self._max_analysis_group_size}"
                    )
                for member in cluster.members:
                    if member in active_members:
                        issues.append(
                            f"{member}: appears in multiple clusters"
                        )
                    active_members[member] = cluster_id
                    if self._cluster_map.get(member) != cluster_id:
                        issues.append(
                            f"{member}: cluster_map does not match membership"
                        )

            for crash_id, cluster_id in self._cluster_map.items():
                if crash_id not in self._records:
                    issues.append(f"{crash_id}: mapped but record is missing")
                if cluster_id not in self._clusters:
                    issues.append(f"{crash_id}: cluster is missing")
                if crash_id not in active_members:
                    issues.append(
                        f"{crash_id}: mapped but absent from cluster members"
                    )

            for crash_id in self._records:
                if crash_id not in self._cluster_map:
                    issues.append(f"{crash_id}: record is not mapped")

            for key, representative in self._exact_index.items():
                if key != self._records[representative].signature:
                    issues.append(f"exact index mismatch for {representative}")
                if not self._is_representative(representative):
                    issues.append(f"exact index points to non-leader {representative}")

            for key, representative in self._stack_index.items():
                if key != self._records[representative].stack_signature:
                    issues.append(f"stack index mismatch for {representative}")
                if not self._is_representative(representative):
                    issues.append(f"stack index points to non-leader {representative}")

            return issues

    def _is_representative(self, crash_id: str) -> bool:
        cluster_id = self._cluster_map.get(crash_id)
        return bool(
            cluster_id
            and cluster_id in self._clusters
            and self._clusters[cluster_id].representative == crash_id
        )

    # ------ Persistence ------

    def save_to_file(self, path: str) -> None:
        """Atomically persist the current state."""
        with self._lock:
            issues = self.validate_state()
            if issues:
                raise ValueError(
                    "refusing to persist inconsistent dedup state: "
                    + "; ".join(issues[:5])
                )
            data = {
                "schema_version": DEDUP_SCHEMA_VERSION,
                "max_analysis_group_size": self._max_analysis_group_size,
                "next_discovery_index": self._next_discovery_index,
                "records": {
                    crash_id: asdict(record)
                    for crash_id, record in self._records.items()
                },
                "clusters": {
                    cluster_id: asdict(cluster)
                    for cluster_id, cluster in self._clusters.items()
                },
                "cluster_map": dict(self._cluster_map),
                "representatives": list(self._representatives),
                "match_levels": dict(self._match_levels),
            }
            directory = os.path.dirname(path) or "."
            os.makedirs(directory, exist_ok=True)
            temporary = f"{path}.tmp.{os.getpid()}"
            try:
                with open(temporary, "w", encoding="utf-8") as handle:
                    yaml.safe_dump(
                        data,
                        handle,
                        default_flow_style=False,
                        allow_unicode=True,
                        sort_keys=False,
                    )
                os.replace(temporary, path)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)

    def load_from_file(self, path: str) -> bool:
        """Load a database and rebuild indexes/clusters from its records.

        Stored cluster membership is treated as a cache, not as the source of
        truth. Replaying records prevents historical truncated cluster IDs from
        resurrecting overwritten or orphaned membership.

        Legacy databases are migrated in a conservative mode: exact signatures
        remain usable, but their old project-only stack keys are not used for
        matching because they were produced by a different stack definition.
        """
        if not os.path.isfile(path):
            return False

        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = yaml.safe_load(handle)
            if not isinstance(data, dict):
                return False

            schema_version = int(data.get("schema_version") or 1)
            if schema_version > DEDUP_SCHEMA_VERSION:
                raise ValueError(
                    f"unsupported dedup schema version {schema_version}"
                )
            legacy_stack_keys = schema_version < DEDUP_SCHEMA_VERSION
            raw_records = data.get("records") or {}
            if not isinstance(raw_records, dict):
                return False

            loaded = DeduplicationEngine()
            loaded._max_analysis_group_size = int(
                data.get("max_analysis_group_size")
                or loaded._max_analysis_group_size
            )
            ordered_records = list(raw_records.items())
            ordered_records.sort(
                key=lambda entry: (
                    int(
                        (
                            (entry[1] or {}).get("discovery_index")
                            if isinstance(entry[1], dict)
                            else 0
                        )
                        or 0
                    ),
                )
            )

            for crash_id, raw_record in ordered_records:
                if not isinstance(raw_record, dict):
                    raise ValueError(f"record {crash_id} is not a mapping")
                record = CrashRecord(**raw_record)
                if legacy_stack_keys:
                    # The old key used a project-only prefix and is not
                    # equivalent to the current non-runtime project/driver
                    # prefix. Clear it before the migrated DB can be saved as
                    # schema v2, otherwise a subsequent load would re-enable an
                    # incompatible relation.
                    record.stack_signature = ""
                loaded._next_discovery_index = max(
                    loaded._next_discovery_index,
                    record.discovery_index + 1,
                )
                loaded._place_record(
                    record,
                    stack_key_override="" if legacy_stack_keys else None,
                )

            stored_next = int(data.get("next_discovery_index") or 0)
            loaded._next_discovery_index = max(
                loaded._next_discovery_index,
                stored_next,
            )
            stored_levels = data.get("match_levels") or {}
            if isinstance(stored_levels, dict):
                loaded._match_levels.update(
                    {
                        str(key): str(value)
                        for key, value in stored_levels.items()
                        if key in loaded._records
                    }
                )

            issues = loaded.validate_state()
            if issues:
                raise ValueError(
                    "rebuilt dedup state is inconsistent: "
                    + "; ".join(issues[:5])
                )

            with self._lock:
                self.__dict__.update(loaded.__dict__)
                self._lock = RLock()

            mode = "legacy exact-only migration" if legacy_stack_keys else "native"
            logger.info(
                f"Loaded dedup DB ({mode}): "
                f"{len(self._records)} records, {len(self._clusters)} clusters"
            )
            return True
        except Exception as exc:
            logger.error(f"Failed to load dedup DB from {path}: {exc}")
            return False
