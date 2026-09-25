import json
import unittest

from ipsec_sentinel.dataset.models import (
    CleanupState,
    DatasetCaptureEvidence,
    DatasetGroundTruth,
    DatasetTrafficEvidence,
    DatasetValidation,
    DatasetVerification,
    ReproducibilityMetadata,
    RunState,
)
from ipsec_sentinel.models import (
    Check,
    ConfiguredPolicy,
    ObservedState,
    PfsObservation,
    StageRecord,
)


def example_truth(
    *,
    status: RunState = RunState.PASS,
    cleanup_status: CleanupState = CleanupState.PASS,
    training_ready: bool = True,
) -> DatasetGroundTruth:
    return DatasetGroundTruth(
        schema_version="ipsec-sentinel.dataset-ground-truth/v1",
        run_id="run_000001",
        slot_id="run_000001",
        attempt_number=1,
        status=status,
        training_ready=training_ready,
        traffic=DatasetTrafficEvidence(
            "video",
            True,
            "supervised",
            "local-segmented-video",
            "1",
            7,
            {"segments": 5},
            {"completed_segments": 5},
        ),
        scenario_id="secure-baseline",
        scenario_schema_version="ipsec-sentinel.scenario/v1",
        configured=ConfiguredPolicy(
            2,
            "tunnel",
            "aes256gcm16-prfsha384-ecp384",
            "aes256gcm16-ecp384",
            True,
            4,
            "10.10.0.0/24",
            "10.20.0.0/24",
            "192.0.2.0/30",
        ),
        observed=ObservedState(
            2,
            "AES_GCM_16_256/PRF_HMAC_SHA2_384/ECP_384",
            "AES_GCM_16_256/NO_EXT_SEQ",
            PfsObservation("VERIFIED", True, ("fresh DH",)),
        ),
        network={
            "profile": "clean",
            "latency_ms": 0,
            "jitter_ms": 0,
            "packet_loss_percent": 0,
            "bandwidth_limit_bps": None,
        },
        capture=DatasetCaptureEvidence(
            "full-evidence.pcap",
            "encrypted.pcap",
            1_000,
            2_000,
            30,
            8,
            22,
            14,
            4096,
            0.000001,
            "pcap-workload-window-esp/v1",
        ),
        validation=DatasetValidation(
            True, True, True, cleanup_status is CleanupState.PASS
        ),
        cleanup_status=cleanup_status,
        reproducibility=ReproducibilityMetadata(
            "a" * 40,
            False,
            None,
            "ipsec-sentinel.dataset-ground-truth/v1",
            "ipsec-sentinel.scenario/v1",
            1,
            "strongSwan 6.0.4",
            "6.18.33.2-microsoft-standard-WSL2",
            "#1 SMP",
            "CPython",
            "3.14.0",
            "Linux",
            "x86_64",
            "local-segmented-video",
            "1",
            "sha256-slot-attempt/v1",
            7,
            "b" * 64,
            "2026-09-24T10:00:00Z",
            "2026-09-24T10:00:01Z",
            1_000,
            2_000,
            (),
        ),
    )


class DatasetModelTest(unittest.TestCase):
    def test_ground_truth_keeps_ipsec_views_and_capture_roles_separate(self) -> None:
        payload = example_truth().to_dict()
        self.assertEqual(
            payload["schema_version"], "ipsec-sentinel.dataset-ground-truth/v1"
        )
        self.assertEqual(
            payload["ipsec"]["configured"]["esp_proposal"],
            "aes256gcm16-ecp384",
        )
        self.assertEqual(
            payload["ipsec"]["observed"]["esp_proposal"],
            "AES_GCM_16_256/NO_EXT_SEQ",
        )
        self.assertEqual(payload["capture"]["full_evidence_file"], "full-evidence.pcap")
        self.assertEqual(payload["capture"]["ml_input_file"], "encrypted.pcap")
        self.assertTrue(payload["training_ready"])
        self.assertTrue(payload["traffic"]["known_training_class"])
        self.assertEqual(payload["traffic"]["class_role"], "supervised")
        self.assertEqual(json.loads(json.dumps(payload)), payload)

    def test_training_ready_requires_pass_and_successful_cleanup(self) -> None:
        with self.assertRaisesRegex(ValueError, "training_ready"):
            example_truth(status=RunState.FAILED, training_ready=True)
        with self.assertRaisesRegex(ValueError, "cleanup"):
            example_truth(cleanup_status=CleanupState.FAILED, training_ready=True)

    def test_dataset_verification_serializes_schema_stages_and_checks(self) -> None:
        verification = DatasetVerification(
            "ipsec-sentinel.dataset-verification/v1",
            "run_000001",
            RunState.FAILED,
            (StageRecord("traffic_validate", "FAIL", "missing receipt"),),
            (Check("traffic.web.receipts", False, ("expected=6", "actual=5")),),
            ({"name": "topology_reset", "status": "PASS", "error": None},),
        )
        payload = verification.to_dict()
        self.assertEqual(
            payload["schema_version"], "ipsec-sentinel.dataset-verification/v1"
        )
        self.assertEqual(payload["status"], "FAILED")
        self.assertFalse(payload["checks"][0]["passed"])


if __name__ == "__main__":
    unittest.main()
