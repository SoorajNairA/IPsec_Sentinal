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
        self.assertEqual(config.evaluation_ood_classes, ())
        self.assertEqual(config.evaluation_runs_per_combination, 0)

    def test_loads_four_scenario_prototype_contract(self) -> None:
        config = self.load(
            VALID.replace(
                "[icmp, web, video]",
                "[icmp, web, video, voip, email, messaging, file_transfer]",
            ).replace(
                "[secure-baseline]",
                "[secure-baseline, aes128-gcm, aes256-cbc, no-pfs]",
            ).replace("runs_per_combination: 3", "runs_per_combination: 6")
        )

        self.assertEqual(
            config.scenarios,
            ("secure-baseline", "aes128-gcm", "aes256-cbc", "no-pfs"),
        )
        self.assertEqual(len(config.traffic_classes), 7)
        self.assertEqual(config.runs_per_combination, 6)

    def test_rejects_scenarios_outside_the_allowlist(self) -> None:
        with self.assertRaisesRegex(DatasetConfigError, "IPsec scenario"):
            self.load(VALID.replace("secure-baseline", "experimental"))

    def test_loads_separate_ood_evaluation_selection(self) -> None:
        config = self.load(
            VALID.replace(
                "execution:\n",
                "evaluation:\n"
                "  ood_classes: [remote_desktop_like, database_query_like]\n"
                "  runs_per_combination: 2\n"
                "execution:\n",
            )
        )
        self.assertEqual(
            config.evaluation_ood_classes,
            ("remote_desktop_like", "database_query_like"),
        )
        self.assertEqual(config.evaluation_runs_per_combination, 2)

    def test_rejects_mixed_or_unknown_class_roles(self) -> None:
        cases = (
            (VALID.replace("icmp, web, video", "icmp, remote_desktop_like"), "OOD"),
            (
                VALID.replace(
                    "execution:\n",
                    "evaluation:\n"
                    "  ood_classes: [web]\n"
                    "  runs_per_combination: 1\n"
                    "execution:\n",
                ),
                "supervised",
            ),
            (VALID.replace("icmp, web, video", "icmp, dns"), "unknown"),
        )
        for text, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(
                DatasetConfigError, message
            ):
                self.load(text)

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
