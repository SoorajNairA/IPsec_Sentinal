from pathlib import Path
from tempfile import TemporaryDirectory
import json
import unittest

from ipsec_sentinel.dataset.summary import DatasetSummary, write_summary


class DatasetSummaryTest(unittest.TestCase):
    def test_json_summary_is_atomic_and_machine_readable(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            summary = DatasetSummary(
                "test", "v1", "f" * 64, 5, 3, 1, 0, 1,
                {"PASS": 3, "FAILED": 1, "INCOMPLETE": 1},
                3, {"icmp": 1, "video": 1, "web": 1},
                {"traffic_generator_failed": 1}, 42, 4096, 3.5,
                "2026-09-25T00:00:00Z", "2026-09-25T00:00:01Z",
                3, 0, {"icmp": 1, "video": 1, "web": 1}, {},
            )
            write_summary(root / "dataset_summary.json", summary)
            payload = json.loads((root / "dataset_summary.json").read_text())
            self.assertEqual(payload["training_ready_runs"], 3)
            self.assertEqual(payload["class_distribution"], {
                "icmp": 1, "video": 1, "web": 1,
            })
            self.assertEqual(payload["supervised_ready_runs"], 3)
            self.assertEqual(payload["ood_ready_runs"], 0)
            self.assertEqual(list(root.glob("*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
