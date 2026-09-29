from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import json
import os
import unittest

from ipsec_sentinel.artifacts import (
    REQUIRED_SUCCESS_FILES,
    create_run_dir,
    publish_results,
    write_json_atomic,
    write_success_artifacts,
    write_text_atomic,
)
from ipsec_sentinel.models import (
    CaptureEvidence,
    Check,
    ConfiguredPolicy,
    GroundTruth,
    ObservedState,
    PfsObservation,
    StageRecord,
    TrafficEvidence,
    Verification,
)


def results(*, status: str = "PASS", check_passed: bool = True):
    verification = Verification(
        "run_20260923T150000Z",
        status,
        (StageRecord("verdict", status, "test"),),
        (Check("required", check_passed, ("fixture",)),),
    )
    truth = GroundTruth(
        run_id=verification.run_id,
        scenario_id="secure-baseline",
        status=status,
        configured=ConfiguredPolicy(
            2, "tunnel", "aes256gcm16-prfsha384-ecp384",
            "aes256gcm16-ecp384", True, 4,
            "10.10.0.0/24", "10.20.0.0/24", "192.0.2.0/30",
        ),
        observed=ObservedState(
            2, "AES_GCM_16_256/PRF_HMAC_SHA2_384/ECP_384",
            "AES_GCM_16_256/NO_EXT_SEQ", PfsObservation.not_tested(),
        ),
        traffic=TrafficEvidence("icmp", 5, 5, True),
        capture=CaptureEvidence("encrypted.pcap", 14, 4, 10, 0, 0),
    )
    return verification, truth


class ArtifactTest(unittest.TestCase):
    def test_run_directories_are_collision_safe_and_private(self) -> None:
        with TemporaryDirectory() as directory:
            now = datetime(2026, 9, 23, 15, 0, tzinfo=timezone.utc)
            first = create_run_dir(Path(directory), now)
            second = create_run_dir(Path(directory), now)

            self.assertNotEqual(first, second)
            self.assertEqual(first.name, "run_20260923T150000Z")
            self.assertEqual(second.name, "run_20260923T150000Z-01")
            self.assertEqual(os.stat(first).st_mode & 0o777, 0o750)

    def test_atomic_writes_replace_content_without_temp_files(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            write_text_atomic(root / "run.log", "old")
            write_text_atomic(root / "run.log", "new")
            write_json_atomic(root / "verification.json", {"status": "FAIL"})

            self.assertEqual((root / "run.log").read_text(), "new")
            self.assertEqual(json.loads((root / "verification.json").read_text())["status"], "FAIL")
            self.assertEqual(list(root.glob("*.tmp")), [])

    def test_success_bundle_has_required_files_and_separate_policy_views(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            verification, truth = results()
            (root / "encrypted.pcap").write_bytes(b"pcap fixture")
            write_success_artifacts(
                root,
                scenario_yaml="id: secure-baseline\n",
                run_log="complete\n",
                sas={"gateway-a": "sa-a", "gateway-b": "sa-b"},
                xfrm={"gateway-a": "xfrm-a", "gateway-b": "xfrm-b"},
                verification=verification,
                ground_truth=truth,
            )

            self.assertTrue(REQUIRED_SUCCESS_FILES.issubset({path.name for path in root.iterdir()}))
            payload = json.loads((root / "ground_truth.json").read_text())
            self.assertNotEqual(payload["configured"]["ike_proposal"], payload["observed"]["ike_proposal"])

    def test_rejects_pass_when_a_required_check_failed(self) -> None:
        with TemporaryDirectory() as directory:
            verification, truth = results(check_passed=False)
            with self.assertRaisesRegex(ValueError, "failed check"):
                publish_results(Path(directory), verification, truth)

    def test_failure_stages_are_published_without_ground_truth(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            verification, _ = results(status="FAIL", check_passed=False)
            publish_results(root, verification, None)
            payload = json.loads((root / "verification.json").read_text())
            self.assertEqual(payload["stages"][0]["status"], "FAIL")
            self.assertFalse((root / "ground_truth.json").exists())


if __name__ == "__main__":
    unittest.main()
