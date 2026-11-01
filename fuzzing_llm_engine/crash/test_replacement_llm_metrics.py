import unittest

from crash.replacement_llm_metrics import expanded_metrics, representative_metrics


class ReplacementMetricsGroundTruthTest(unittest.TestCase):
    def setUp(self):
        self.key = ("project", "representative")
        self.baseline = {
            self.key: {
                "Project": "project",
                "CrashID": "representative",
                "GroundTruth": "FALSE",
                "MemberGroundTruth": "TRUE",
            }
        }
        self.results = {
            self.key: {
                "Result": "true",
            }
        }
        self.mapping = {
            self.key: {
                "RepresentativeCrashID": "representative",
            }
        }

    def test_representative_metrics_prefer_member_ground_truth(self):
        rows = representative_metrics(self.results, self.baseline)

        self.assertTrue(rows[0]["GroundTruth"])

    def test_expanded_metrics_prefer_member_ground_truth(self):
        rows = expanded_metrics(self.results, self.baseline, self.mapping)

        self.assertTrue(rows[0]["GroundTruth"])


if __name__ == "__main__":
    unittest.main()
