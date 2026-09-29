import hashlib
import unittest

from ipsec_sentinel.dataset.runner import minimum_esp_packets
from ipsec_sentinel.traffic.file_transfer import (
    FileTransferGenerator,
    expected_transfer_records,
    resolve_file_transfer_plan,
    validate_file_transfer_result,
)
from ipsec_sentinel.traffic.file_transfer_peer import iter_deterministic_chunks


class FileTransferGeneratorTest(unittest.TestCase):
    def test_same_seed_reproduces_plan_and_seed_set_varies_bulk_behavior(self) -> None:
        first = resolve_file_transfer_plan(701)
        self.assertEqual(first, resolve_file_transfer_plan(701))
        plans = [resolve_file_transfer_plan(seed) for seed in range(701, 741)]
        self.assertEqual(
            {plan.direction for plan in plans},
            {"upload", "download", "bidirectional"},
        )
        self.assertGreater(len({plan.total_payload_bytes for plan in plans}), 1)
        self.assertGreater(
            len({tuple(leg.write_bytes for leg in plan.legs) for plan in plans}),
            1,
        )
        self.assertGreater(
            len({tuple(leg.writes_per_group for leg in plan.legs) for plan in plans}),
            1,
        )
        self.assertGreater(
            len({tuple(leg.group_gap_seconds for leg in plan.legs) for plan in plans}),
            1,
        )
        for plan in plans:
            self.assertGreaterEqual(plan.total_payload_bytes, 1024 * 1024)
            self.assertLessEqual(plan.total_payload_bytes, 8 * 1024 * 1024)
            self.assertFalse(hasattr(plan, "segments"))
            self.assertFalse(hasattr(plan, "playback_pacing_seconds"))

    def test_incremental_content_is_exact_reproducible_and_seeded(self) -> None:
        first = list(iter_deterministic_chunks(701, "transfer-1", 10_003, 1024))
        repeated = list(iter_deterministic_chunks(701, "transfer-1", 10_003, 1024))
        changed = list(iter_deterministic_chunks(702, "transfer-1", 10_003, 1024))
        self.assertEqual(first, repeated)
        self.assertNotEqual(first, changed)
        self.assertEqual(sum(len(chunk) for chunk in first), 10_003)
        self.assertEqual(len(first), 10)
        self.assertEqual(
            hashlib.sha256(b"".join(first)).hexdigest(),
            hashlib.sha256(b"".join(repeated)).hexdigest(),
        )

    def test_validation_requires_matching_bytes_digests_and_completions(self) -> None:
        plan = resolve_file_transfer_plan(701)
        expected = expected_transfer_records(plan, 701)
        upload = [item for item in expected if item["direction"] == "client_to_server"]
        download = [item for item in expected if item["direction"] == "server_to_client"]
        client = {
            "sent": upload,
            "received": download,
            "connection_count": 1,
            "completion_count": len(expected),
        }
        server = {
            "sent": download,
            "received": upload,
            "connection_count": 1,
            "completion_count": len(expected),
        }
        valid = validate_file_transfer_result(plan, client, server, seed=701)
        self.assertTrue(valid.passed, valid.errors)

        corrupted = [dict(item) for item in upload]
        corrupted[0]["payload_sha256"] = "0" * 64
        invalid_server = dict(server, received=corrupted)
        invalid = validate_file_transfer_result(
            plan, client, invalid_server, seed=701
        )
        self.assertFalse(invalid.passed)
        self.assertTrue(any("integrity" in error for error in invalid.errors))

    def test_metadata_records_bulk_parameters_and_esp_floor_is_conservative(self) -> None:
        generator = FileTransferGenerator(701)
        metadata = generator.metadata()
        self.assertEqual(metadata["class"], "file_transfer")
        self.assertTrue(metadata["known_training_class"])
        parameters = metadata["parameters"]
        self.assertEqual(parameters["direction"], generator.plan.direction)
        self.assertEqual(parameters["total_payload_bytes"], generator.plan.total_payload_bytes)
        self.assertEqual(len(parameters["legs"]), len(generator.plan.legs))
        self.assertEqual(
            minimum_esp_packets("file_transfer", parameters),
            max(100, generator.plan.total_payload_bytes // (128 * 1024)),
        )


if __name__ == "__main__":
    unittest.main()
