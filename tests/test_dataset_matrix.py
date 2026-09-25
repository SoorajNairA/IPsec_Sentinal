from dataclasses import replace
import unittest

from ipsec_sentinel.dataset.config import DatasetConfig
from ipsec_sentinel.dataset.matrix import (
    attempt_id,
    derive_attempt_seed,
    expand_matrix,
    matrix_fingerprint,
)
from ipsec_sentinel.scenario import scenario_digest


class MatrixTest(unittest.TestCase):
    def setUp(self) -> None:
        self.config = DatasetConfig(
            name="cipherlens-smoke-v1",
            schema_version="ipsec-sentinel.dataset-ground-truth/v1",
            base_seed=20260924,
            traffic_classes=("icmp", "web", "video"),
            scenarios=("secure-baseline",),
            network_profiles=("clean",),
            runs_per_combination=3,
            workers=1,
            retry_failed=1,
            evaluation_ood_classes=(),
            evaluation_runs_per_combination=0,
        )
        self.versions = {"icmp": "1", "web": "1", "video": "1"}

    def test_expands_nine_stable_slots_in_declared_order(self) -> None:
        slots = expand_matrix(self.config, self.versions)
        self.assertEqual(len(slots), 9)
        self.assertEqual(slots[0].slot_id, "run_000001")
        self.assertEqual(slots[0].traffic_class, "icmp")
        self.assertEqual(slots[3].traffic_class, "web")
        self.assertEqual(slots[6].traffic_class, "video")
        self.assertEqual(slots[-1].slot_id, "run_000009")

    def test_seed_is_repeatable_and_changes_for_retry(self) -> None:
        first = derive_attempt_seed(20260924, ordinal=1, attempt_number=1)
        self.assertEqual(first, derive_attempt_seed(20260924, 1, 1))
        self.assertNotEqual(first, derive_attempt_seed(20260924, 1, 2))
        self.assertEqual(attempt_id("run_000001", 1), "run_000001")
        self.assertEqual(attempt_id("run_000001", 2), "run_000001-attempt02")

    def test_fingerprint_changes_for_order_seed_or_generator_version(self) -> None:
        original = matrix_fingerprint(self.config, self.versions)
        reordered = replace(self.config, traffic_classes=("web", "icmp", "video"))
        reseeded = replace(self.config, base_seed=7)
        self.assertNotEqual(original, matrix_fingerprint(reordered, self.versions))
        self.assertNotEqual(original, matrix_fingerprint(reseeded, self.versions))
        self.assertNotEqual(
            original,
            matrix_fingerprint(self.config, {**self.versions, "web": "2"}),
        )

    def test_prototype_expands_168_slots_and_fingerprints_scenario_files(self) -> None:
        classes = (
            "icmp", "web", "video", "voip", "email", "messaging",
            "file_transfer",
        )
        scenarios = ("secure-baseline", "aes128-gcm", "aes256-cbc", "no-pfs")
        config = replace(
            self.config,
            traffic_classes=classes,
            scenarios=scenarios,
            runs_per_combination=6,
        )
        versions = {name: "1" for name in classes}

        slots = expand_matrix(config, versions)

        self.assertEqual(len(slots), 168)
        self.assertEqual(slots[0].scenario_id, "secure-baseline")
        self.assertEqual(slots[42].scenario_id, "aes128-gcm")
        self.assertEqual(slots[-1].scenario_id, "no-pfs")
        self.assertRegex(scenario_digest("aes256-cbc"), r"^[0-9a-f]{64}$")
        self.assertNotEqual(
            matrix_fingerprint(config, versions),
            matrix_fingerprint(replace(config, scenarios=scenarios[::-1]), versions),
        )


if __name__ == "__main__":
    unittest.main()
