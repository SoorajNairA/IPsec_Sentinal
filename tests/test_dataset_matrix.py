from dataclasses import replace
import unittest

from ipsec_sentinel.dataset.config import DatasetConfig
from ipsec_sentinel.dataset.matrix import (
    attempt_id,
    derive_attempt_seed,
    expand_matrix,
    matrix_fingerprint,
)


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


if __name__ == "__main__":
    unittest.main()
