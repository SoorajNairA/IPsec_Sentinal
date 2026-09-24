from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from ipsec_sentinel.dataset.config import DatasetConfig, DatasetConfigError

VALID = """dataset:
  name: cipherlens-smoke-v1
  schema_version: ipsec-sentinel.dataset-ground-truth/v1
  seed: 20260924
traffic:
  classes: [icmp, web, video]
ipsec:
  scenarios: [secure-baseline]
network_profiles: [clean]
runs_per_combination: 3
execution:
  workers: 1
  retry_failed: 1
"""


class DatasetConfigTest(unittest.TestCase):
    def load(self, text: str) -> DatasetConfig:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "matrix.yaml"
            path.write_text(text, encoding="utf-8")
            return DatasetConfig.load(path)

    def test_loads_exact_smoke_contract(self) -> None:
        config = self.load(VALID)
        self.assertEqual(config.name, "cipherlens-smoke-v1")
        self.assertEqual(config.traffic_classes, ("icmp", "web", "video"))
        self.assertEqual(config.runs_per_combination, 3)
        self.assertEqual(config.workers, 1)

    def test_rejects_unknown_fields_parallelism_and_unsupported_profiles(self) -> None:
        for text, message in (
            (VALID + "extra: true\n", "unknown field"),
            (VALID.replace("workers: 1", "workers: 2"), "workers"),
            (VALID.replace("[clean]", "[latency-40ms]"), "network profile"),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(
                DatasetConfigError, message
            ):
                self.load(text)


if __name__ == "__main__":
    unittest.main()
