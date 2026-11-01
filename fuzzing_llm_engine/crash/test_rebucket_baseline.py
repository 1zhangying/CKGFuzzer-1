from __future__ import annotations

import unittest

from crash.rebucket_baseline import (
    ReBucketRecord,
    ReBucketSettings,
    apply_group_size_limit,
    cluster_records,
    pdd_distance,
)


class ReBucketBaselineTest(unittest.TestCase):
    def setUp(self) -> None:
        self.settings = ReBucketSettings()

    def test_identical_stacks_have_zero_distance(self) -> None:
        stack = ("crash", "api", "driver")
        self.assertEqual(pdd_distance(stack, stack, self.settings), 0.0)

    def test_one_frame_stacks_remain_separate(self) -> None:
        self.assertEqual(
            pdd_distance(("crash",), ("crash",), self.settings),
            1.0,
        )

    def test_identical_multiframe_stacks_cluster(self) -> None:
        records = [
            ReBucketRecord("p", "a", "d", ("crash", "api", "driver")),
            ReBucketRecord("p", "b", "d", ("crash", "api", "driver")),
            ReBucketRecord("p", "c", "d", ("crash", "other", "driver")),
        ]
        groups = cluster_records(records, self.settings)
        self.assertEqual(groups, [[0, 1], [2]])

    def test_projects_never_merge(self) -> None:
        frames = ("crash", "api", "driver")
        records = [
            ReBucketRecord("p1", "a", "d", frames),
            ReBucketRecord("p2", "b", "d", frames),
        ]
        self.assertEqual(cluster_records(records, self.settings), [[0], [1]])

    def test_group_size_limit_splits_deterministically(self) -> None:
        self.assertEqual(
            apply_group_size_limit([[0, 1, 2, 3, 4, 5, 6, 7]], 7),
            [[0, 1, 2, 3, 4, 5, 6], [7]],
        )


if __name__ == "__main__":
    unittest.main()
