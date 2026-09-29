from pathlib import Path
from tempfile import TemporaryDirectory
import csv
import json
import unittest

from ipsec_sentinel.ml.dataset import build_feature_dataset
from ipsec_sentinel.ml.split import build_grouped_split
from tests.test_ml_dataset import build_valid_source


class MlSplitTest(unittest.TestCase):
    def test_six_session_stratum_is_deterministic_four_one_one(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            built = build_feature_dataset(build_valid_source(root), root / "ml")
            first = build_grouped_split(
                built.features_csv, root / "split-a.json", seed=20260926
            )
            second = build_grouped_split(
                built.features_csv, root / "split-b.json", seed=20260926
            )
            payload = json.loads(first.path.read_text(encoding="utf-8"))

        self.assertEqual(first.assignments, second.assignments)
        counts = {name: 0 for name in ("train", "validation", "test")}
        seen: set[str] = set()
        for assignment in payload["assignments"]:
            self.assertNotIn(assignment["session_id"], seen)
            seen.add(assignment["session_id"])
            counts[assignment["split"]] += 1
        self.assertEqual(counts, {"train": 4, "validation": 1, "test": 1})

    def test_sparse_pilot_strata_prioritize_training_coverage(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "features.csv"
            with path.open("w", newline="", encoding="utf-8") as output:
                writer = csv.DictWriter(
                    output, fieldnames=("session_id", "label", "scenario_id", "packet_count")
                )
                writer.writeheader()
                writer.writerows(
                    (
                        {"session_id": "one", "label": "voip", "scenario_id": "secure-baseline", "packet_count": 10},
                        {"session_id": "two", "label": "email", "scenario_id": "secure-baseline", "packet_count": 12},
                    )
                )
            result = build_grouped_split(path, root / "split.json", seed=1)

        self.assertEqual(
            {item["session_id"]: item["split"] for item in result.assignments},
            {"one": "train", "two": "train"},
        )


if __name__ == "__main__":
    unittest.main()
