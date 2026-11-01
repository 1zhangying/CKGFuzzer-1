#!/usr/bin/env python3
"""Reproduce the ReBucket crash-report clustering baseline.

The implementation follows the PDM distance and complete-link clustering
rules described by Dang et al. (ICSE 2012).  The distance coefficients and
threshold match the public research implementation maintained at
https://github.com/ZhangShurong/rebucket, commit
2e6d5845aedabbfe3800de1a1f6b86498841ee2d.

This is an independent reproduction, not code published by the ReBucket
authors.  It intentionally performs no LLM calls and does not modify the
CrashSage deduplication mapping.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import heapq
import json
import math
import statistics
from array import array
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Sequence, Tuple

import yaml

from .sanitizer_parser import parse_sanitizer_output


DEFAULT_MAPPING = Path(
    "results/dedup_schema2_14projects_20261027/dedup_mapping_14projects.csv"
)
DEFAULT_OUTPUT = Path("results/rebucket_baseline_20261030")

MAPPING_FIELDS = [
    "Project",
    "CrashID",
    "Driver",
    "RepresentativeCrashID",
    "IsDuplicate",
    "ClusterID",
    "ClusterSize",
    "FrameCount",
    "StackSHA256",
]
REPRESENTATIVE_FIELDS = [
    "Project",
    "CrashID",
    "Driver",
    "ClusterID",
    "ClusterSize",
    "FrameCount",
    "StackSHA256",
]
PROJECT_SUMMARY_FIELDS = [
    "Project",
    "Samples",
    "Clusters",
    "Singletons",
    "LargestCluster",
]
COMPARISON_FIELDS = ["Metric", "CrashSage", "ReBucket"]


@dataclass(frozen=True)
class ReBucketRecord:
    project: str
    crash_id: str
    driver: str
    frames: Tuple[str, ...]


@dataclass(frozen=True)
class ReBucketSettings:
    top_frame_weight: float = 0.04
    alignment_weight: float = 0.13
    distance_threshold: float = 0.06


def _read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def _write_csv(path: Path, fields: Sequence[str], rows: Iterable[Mapping[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fields), extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fields})


def _load_crash_entries(db_root: Path, projects: Iterable[str]) -> Dict[Tuple[str, str], Dict[str, object]]:
    entries: Dict[Tuple[str, str], Dict[str, object]] = {}
    for project in sorted(set(projects)):
        crash_root = db_root / project / "crash"
        for yaml_path in sorted(crash_root.glob("*/crash_analysis.yaml")):
            driver = yaml_path.parent.name
            data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or []
            if not isinstance(data, list):
                continue
            for item in data:
                if not isinstance(item, dict):
                    continue
                for local_id, entry in item.items():
                    if isinstance(entry, dict):
                        entries[(project, f"{driver}_{local_id}")] = entry
    return entries


def _is_runtime_frame(function: str, file_path: str) -> bool:
    lowered_path = file_path.lower()
    lowered_function = function.lower()
    return (
        "llvm-project" in lowered_path
        or "lib/fuzzer" in lowered_path
        or lowered_function.startswith("fuzzer::")
        or lowered_function.startswith("__asan")
        or lowered_function.startswith("__msan")
        or lowered_function.startswith("__tsan")
        or lowered_function.startswith("__interceptor")
    )


def normalized_frames(entry: Mapping[str, object], crash_id: str) -> Tuple[str, ...]:
    """Extract an ordered top-to-bottom function stack.

    ReBucket ignores system/runtime frames.  We additionally collapse adjacent
    duplicates, which commonly appear for inlined sanitizer frames.
    """
    crash_info = str(entry.get("crash_info") or "")
    if crash_info.startswith("|"):
        crash_info = crash_info[1:].lstrip("\n")
    parsed = parse_sanitizer_output(crash_info)
    frames: List[str] = []
    for frame in parsed.get("frames") or []:
        function = str(frame.get("func") or "").strip()
        file_path = str(frame.get("file") or "")
        if not function or _is_runtime_frame(function, file_path):
            continue
        if not frames or frames[-1] != function:
            frames.append(function)
    # The public implementation assigns distance one to every one-frame stack.
    # A stable synthetic frame keeps a missing stack as a singleton without
    # merging it with unrelated missing stacks.
    if not frames:
        frames.append(f"<empty:{crash_id}>")
    return tuple(frames)


def load_records(mapping_path: Path, db_root: Path) -> List[ReBucketRecord]:
    mapping_rows = _read_csv(mapping_path)
    required = {"Project", "CrashID", "Driver"}
    missing_fields = required.difference(mapping_rows[0].keys() if mapping_rows else [])
    if missing_fields:
        raise ValueError(f"Mapping is missing columns: {sorted(missing_fields)}")
    entries = _load_crash_entries(
        db_root,
        (row["Project"] for row in mapping_rows),
    )
    records = []
    missing_entries = []
    for row in mapping_rows:
        key = (row["Project"], row["CrashID"])
        entry = entries.get(key)
        if entry is None:
            missing_entries.append(key)
            continue
        records.append(
            ReBucketRecord(
                project=row["Project"],
                crash_id=row["CrashID"],
                driver=row["Driver"],
                frames=normalized_frames(entry, row["CrashID"]),
            )
        )
    if missing_entries:
        preview = ", ".join(f"{project}/{crash}" for project, crash in missing_entries[:5])
        raise ValueError(
            f"{len(missing_entries)} mapping rows have no crash entry; first: {preview}"
        )
    return records


def pdd_distance(
    stack_a: Sequence[str],
    stack_b: Sequence[str],
    settings: ReBucketSettings,
) -> float:
    """Return ReBucket's PDM distance in the range [0, 1]."""
    if len(stack_a) == 1 or len(stack_b) == 1:
        return 1.0

    c = settings.top_frame_weight
    o = settings.alignment_weight
    previous = [0.0] * (len(stack_b) + 1)
    for i, function_a in enumerate(stack_a, 1):
        current = [0.0] * (len(stack_b) + 1)
        for j, function_b in enumerate(stack_b, 1):
            matched = 0.0
            if function_a == function_b:
                matched = math.exp(-c * min(i - 1, j - 1)) * math.exp(
                    -o * abs(i - j)
                )
            current[j] = max(
                previous[j - 1] + matched,
                previous[j],
                current[j - 1],
            )
        previous = current

    normalization = sum(
        math.exp(-c * i) for i in range(min(len(stack_a), len(stack_b)))
    )
    similarity = previous[-1] / normalization
    return max(0.0, min(1.0, 1.0 - similarity))


def cluster_stacks(
    records: Sequence[ReBucketRecord],
    settings: ReBucketSettings,
) -> List[List[int]]:
    """Cluster one project's records with complete-link agglomeration."""
    count = len(records)
    if count == 0:
        return []

    distances = [array("d", [1.0]) * count for _ in range(count)]
    queue: List[Tuple[float, int, int]] = []
    for left in range(count):
        distances[left][left] = 0.0
        for right in range(left + 1, count):
            distance = pdd_distance(
                records[left].frames,
                records[right].frames,
                settings,
            )
            distances[left][right] = distances[right][left] = distance
            if distance < settings.distance_threshold:
                heapq.heappush(queue, (distance, left, right))

    active = [True] * count
    cluster_of = list(range(count))
    members = {index: [index] for index in range(count)}

    while queue:
        distance, cluster_a, cluster_b = heapq.heappop(queue)
        cluster_a = cluster_of[cluster_a]
        cluster_b = cluster_of[cluster_b]
        if (
            cluster_a == cluster_b
            or not active[cluster_a]
            or not active[cluster_b]
            or distance >= settings.distance_threshold
        ):
            continue
        if cluster_a > cluster_b:
            cluster_a, cluster_b = cluster_b, cluster_a

        active[cluster_b] = False
        for member in members[cluster_b]:
            cluster_of[member] = cluster_a
        members[cluster_a].extend(members[cluster_b])
        del members[cluster_b]

        for other in range(count):
            if not active[other] or other == cluster_a:
                continue
            merged_distance = max(
                distances[cluster_a][other],
                distances[cluster_b][other],
            )
            distances[cluster_a][other] = merged_distance
            distances[other][cluster_a] = merged_distance
            if merged_distance < settings.distance_threshold:
                heapq.heappush(queue, (merged_distance, cluster_a, other))

    groups = []
    for root in sorted(index for index, is_active in enumerate(active) if is_active):
        groups.append(sorted(members[root]))
    return groups


def cluster_records(
    records: Sequence[ReBucketRecord],
    settings: ReBucketSettings,
) -> List[List[int]]:
    by_project: Dict[str, List[int]] = defaultdict(list)
    for index, record in enumerate(records):
        by_project[record.project].append(index)

    groups: List[List[int]] = []
    for project in sorted(by_project):
        indices = by_project[project]
        project_records = [records[index] for index in indices]
        for local_group in cluster_stacks(project_records, settings):
            groups.append([indices[local] for local in local_group])
    groups.sort(key=lambda group: min(group))
    return groups


def apply_group_size_limit(
    groups: Sequence[Sequence[int]],
    max_group_size: int | None,
) -> List[List[int]]:
    """Split oversized clusters into deterministic analysis groups."""
    if max_group_size is None:
        return [list(group) for group in groups]
    if max_group_size < 1:
        raise ValueError("max_group_size must be positive")
    limited: List[List[int]] = []
    for group in groups:
        ordered = sorted(group)
        limited.extend(
            ordered[offset : offset + max_group_size]
            for offset in range(0, len(ordered), max_group_size)
        )
    return sorted(limited, key=lambda group: min(group))


def build_outputs(
    records: Sequence[ReBucketRecord],
    groups: Sequence[Sequence[int]],
) -> Tuple[List[Dict[str, object]], List[Dict[str, object]], List[Dict[str, object]]]:
    mapping_rows = []
    representative_rows = []
    project_clusters: Dict[str, int] = Counter()
    project_largest: Dict[str, int] = defaultdict(int)

    for group_number, group in enumerate(groups, 1):
        representative_index = min(group)
        representative = records[representative_index]
        cluster_id = f"rebucket:{group_number:04d}:{representative.crash_id}"
        project_clusters[representative.project] += 1
        project_largest[representative.project] = max(
            project_largest[representative.project],
            len(group),
        )
        for index in group:
            record = records[index]
            stack_hash = hashlib.sha256(
                "\0".join(record.frames).encode("utf-8")
            ).hexdigest()
            is_duplicate = index != representative_index
            mapping_rows.append(
                {
                    "Project": record.project,
                    "CrashID": record.crash_id,
                    "Driver": record.driver,
                    "RepresentativeCrashID": representative.crash_id,
                    "IsDuplicate": str(is_duplicate).lower(),
                    "ClusterID": cluster_id,
                    "ClusterSize": len(group),
                    "FrameCount": len(record.frames),
                    "StackSHA256": stack_hash,
                }
            )
        stack_hash = hashlib.sha256(
            "\0".join(representative.frames).encode("utf-8")
        ).hexdigest()
        representative_rows.append(
            {
                "Project": representative.project,
                "CrashID": representative.crash_id,
                "Driver": representative.driver,
                "ClusterID": cluster_id,
                "ClusterSize": len(group),
                "FrameCount": len(representative.frames),
                "StackSHA256": stack_hash,
            }
        )

    project_counts = Counter(record.project for record in records)
    project_sizes = Counter()
    for group in groups:
        project_sizes[records[min(group)].project] += 1
    project_rows = [
        {
            "Project": project,
            "Samples": project_counts[project],
            "Clusters": project_clusters[project],
            "Singletons": sum(
                1
                for group in groups
                if len(group) == 1 and records[min(group)].project == project
            ),
            "LargestCluster": project_largest[project],
        }
        for project in sorted(project_counts)
    ]
    return mapping_rows, representative_rows, project_rows


def compare_with_crashsage(
    records: Sequence[ReBucketRecord],
    groups: Sequence[Sequence[int]],
    reference_mapping_path: Path,
) -> Tuple[List[Dict[str, object]], Dict[str, object]]:
    reference_rows = _read_csv(reference_mapping_path)
    required = {"Project", "CrashID", "RepresentativeCrashID"}
    missing_fields = required.difference(
        reference_rows[0].keys() if reference_rows else []
    )
    if missing_fields:
        raise ValueError(
            f"CrashSage mapping is missing columns: {sorted(missing_fields)}"
        )
    reference = {
        (row["Project"], row["CrashID"]): row["RepresentativeCrashID"]
        for row in reference_rows
    }
    keys = [(record.project, record.crash_id) for record in records]
    if set(keys) != set(reference):
        missing_reference = set(keys) - set(reference)
        missing_records = set(reference) - set(keys)
        raise ValueError(
            "CrashSage and ReBucket populations differ: "
            f"{len(missing_reference)} missing reference rows, "
            f"{len(missing_records)} extra reference rows"
        )

    rebucket = {
        (record.project, record.crash_id): group_number
        for group_number, group in enumerate(groups)
        for index in group
        for record in (records[index],)
    }
    reference_sizes = Counter(reference.values())
    rebucket_group_sizes = [len(group) for group in groups]
    shared_co_cluster = 0
    crashsage_only = 0
    rebucket_only = 0
    neither = 0
    for left_index, left in enumerate(keys):
        for right in keys[left_index + 1 :]:
            if left[0] != right[0]:
                continue
            in_crashsage = reference[left] == reference[right]
            in_rebucket = rebucket[left] == rebucket[right]
            if in_crashsage and in_rebucket:
                shared_co_cluster += 1
            elif in_crashsage:
                crashsage_only += 1
            elif in_rebucket:
                rebucket_only += 1
            else:
                neither += 1

    crashsage_clusters = len(reference_sizes)
    rebucket_clusters = len(groups)
    crashsage_pairs = shared_co_cluster + crashsage_only
    rebucket_pairs = shared_co_cluster + rebucket_only
    union_pairs = shared_co_cluster + crashsage_only + rebucket_only
    metrics = {
        "samples": len(records),
        "crashsage_clusters": crashsage_clusters,
        "rebucket_clusters": rebucket_clusters,
        "crashsage_reduction": round(1 - crashsage_clusters / len(records), 6),
        "rebucket_reduction": round(1 - rebucket_clusters / len(records), 6),
        "crashsage_llm_submissions": crashsage_clusters,
        "rebucket_llm_submissions": rebucket_clusters,
        "crashsage_singletons": sum(size == 1 for size in reference_sizes.values()),
        "rebucket_singletons": sum(size == 1 for size in rebucket_group_sizes),
        "crashsage_median_group_size": statistics.median(reference_sizes.values()),
        "rebucket_median_group_size": statistics.median(rebucket_group_sizes),
        "crashsage_largest_group": max(reference_sizes.values()),
        "rebucket_largest_group": max(rebucket_group_sizes),
        "crashsage_groups_at_least_8": sum(
            size >= 8 for size in reference_sizes.values()
        ),
        "rebucket_groups_at_least_8": sum(size >= 8 for size in rebucket_group_sizes),
        "shared_co_cluster_pairs": shared_co_cluster,
        "crashsage_only_pairs": crashsage_only,
        "rebucket_only_pairs": rebucket_only,
        "neither_co_cluster_pairs": neither,
        "crashsage_co_cluster_pairs": crashsage_pairs,
        "rebucket_co_cluster_pairs": rebucket_pairs,
        "pairwise_jaccard": round(
            shared_co_cluster / union_pairs if union_pairs else 0.0,
            6,
        ),
        "crashsage_pair_coverage_by_rebucket": round(
            shared_co_cluster / crashsage_pairs if crashsage_pairs else 0.0,
            6,
        ),
    }
    mapping = [
        ("Representative groups", crashsage_clusters, rebucket_clusters),
        (
            "LLM submissions",
            crashsage_clusters,
            rebucket_clusters,
        ),
        (
            "Deduplication ratio",
            metrics["crashsage_reduction"],
            metrics["rebucket_reduction"],
        ),
        (
            "Singleton groups",
            metrics["crashsage_singletons"],
            metrics["rebucket_singletons"],
        ),
        (
            "Median group size",
            metrics["crashsage_median_group_size"],
            metrics["rebucket_median_group_size"],
        ),
        (
            "Largest group",
            metrics["crashsage_largest_group"],
            metrics["rebucket_largest_group"],
        ),
        (
            "Groups with at least 8 reports",
            metrics["crashsage_groups_at_least_8"],
            metrics["rebucket_groups_at_least_8"],
        ),
        (
            "Co-clustered report pairs",
            metrics["crashsage_co_cluster_pairs"],
            metrics["rebucket_co_cluster_pairs"],
        ),
        (
            "Shared co-clustered pairs",
            shared_co_cluster,
            shared_co_cluster,
        ),
        ("CrashSage-only pairs", crashsage_only, 0),
        ("ReBucket-only pairs", 0, rebucket_only),
        ("Pairwise Jaccard agreement", metrics["pairwise_jaccard"], metrics["pairwise_jaccard"]),
        (
            "CrashSage-pair coverage",
            metrics["crashsage_pair_coverage_by_rebucket"],
            metrics["crashsage_pair_coverage_by_rebucket"],
        ),
    ]
    comparison_rows = [
        {"Metric": metric, "CrashSage": left, "ReBucket": right}
        for metric, left, right in mapping
    ]
    return comparison_rows, metrics


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mapping", type=Path, default=DEFAULT_MAPPING)
    parser.add_argument(
        "--db-root",
        type=Path,
        default=Path("external_database"),
    )
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--crashsage-mapping",
        type=Path,
        default=DEFAULT_MAPPING,
    )
    parser.add_argument("--c", type=float, default=0.04)
    parser.add_argument("--o", type=float, default=0.13)
    parser.add_argument("--threshold", type=float, default=0.06)
    parser.add_argument(
        "--max-group-size",
        type=int,
        default=None,
        help="Optional deterministic cap on the number of reports per group.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    settings = ReBucketSettings(
        top_frame_weight=args.c,
        alignment_weight=args.o,
        distance_threshold=args.threshold,
    )
    records = load_records(args.mapping, args.db_root)
    groups = apply_group_size_limit(
        cluster_records(records, settings),
        args.max_group_size,
    )
    mapping_rows, representative_rows, project_rows = build_outputs(records, groups)
    comparison_rows, comparison = compare_with_crashsage(
        records,
        groups,
        args.crashsage_mapping,
    )

    output_dir = args.output_dir
    _write_csv(output_dir / "rebucket_mapping.csv", MAPPING_FIELDS, mapping_rows)
    _write_csv(
        output_dir / "rebucket_representatives.csv",
        REPRESENTATIVE_FIELDS,
        representative_rows,
    )
    _write_csv(
        output_dir / "rebucket_project_summary.csv",
        PROJECT_SUMMARY_FIELDS,
        project_rows,
    )
    _write_csv(
        output_dir / "rebucket_vs_crashsage.csv",
        COMPARISON_FIELDS,
        comparison_rows,
    )
    metadata = {
        "algorithm": "ReBucket PDM distance with complete-link agglomeration",
        "algorithm_reference": "https://doi.org/10.1109/ICSE.2012.6227111",
        "implementation_reference": (
            "https://github.com/ZhangShurong/rebucket/"
            "commit/2e6d5845aedabbfe3800de1a1f6b86498841ee2d"
        ),
        "note": "Independent reproduction, not official author code.",
        "mapping": str(args.mapping),
        "db_root": str(args.db_root),
        "settings": asdict(settings),
        "max_group_size": args.max_group_size,
        "samples": len(records),
        "clusters": len(groups),
        "duplicates_filtered": len(records) - len(groups),
        "dedup_ratio": round(1 - len(groups) / len(records), 6)
        if records
        else 0.0,
        "cluster_size_distribution": dict(
            sorted(Counter(len(group) for group in groups).items())
        ),
        "comparison_with_crashsage": comparison,
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "rebucket_run.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        f"ReBucket: {len(records)} reports -> {len(groups)} clusters; "
        f"output={output_dir}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
