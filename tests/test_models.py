import json
import unittest

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


class ResultModelTest(unittest.TestCase):
    def test_ground_truth_keeps_configured_and_observed_values_separate(self) -> None:
        result = GroundTruth(
            run_id="run_20260923_150000",
            scenario_id="secure-baseline",
            status="PASS",
            configured=ConfiguredPolicy(
                ike_version=2,
                mode="tunnel",
                ike_proposal="aes256gcm16-prfsha384-ecp384",
                esp_proposal="aes256gcm16-ecp384",
                pfs=True,
                ip_version=4,
                local_subnet="10.10.0.0/24",
                remote_subnet="10.20.0.0/24",
                transit_subnet="192.0.2.0/30",
            ),
            observed=ObservedState(
                ike_version=2,
                ike_proposal="AES_GCM_16_256/PRF_HMAC_SHA2_384/ECP_384",
                esp_proposal="AES_GCM_16_256/NO_EXT_SEQ",
                pfs=PfsObservation.not_tested(),
            ),
            traffic=TrafficEvidence(
                type="icmp",
                sent=5,
                received=5,
                success=True,
            ),
            capture=CaptureEvidence(
                pcap="encrypted.pcap",
                packet_count=14,
                ike_packets=4,
                esp_packets=10,
                natt_packets=0,
                cleartext_packets=0,
            ),
        )

        payload = result.to_dict()

        self.assertEqual(
            payload["configured"]["ike_proposal"],
            "aes256gcm16-prfsha384-ecp384",
        )
        self.assertEqual(
            payload["observed"]["ike_proposal"],
            "AES_GCM_16_256/PRF_HMAC_SHA2_384/ECP_384",
        )
        self.assertEqual(
            payload["observed"]["pfs"],
            {"status": "NOT_TESTED", "rekey_observed": False, "evidence": []},
        )
        self.assertEqual(json.loads(json.dumps(payload)), payload)

    def test_verification_serializes_explicit_stage_and_check_status(self) -> None:
        verification = Verification(
            run_id="run_20260923_150000",
            status="FAIL",
            stages=(
                StageRecord(
                    name="pcap_validation",
                    status="FAIL",
                    message="ESP packets missing",
                ),
            ),
            checks=(
                Check(
                    name="capture.esp_present",
                    passed=False,
                    evidence=("esp_packets=0",),
                ),
            ),
        )

        payload = verification.to_dict()

        self.assertEqual(payload["status"], "FAIL")
        self.assertEqual(payload["stages"][0]["name"], "pcap_validation")
        self.assertEqual(payload["stages"][0]["status"], "FAIL")
        self.assertFalse(payload["checks"][0]["passed"])
        self.assertEqual(payload["checks"][0]["evidence"], ["esp_packets=0"])
        self.assertEqual(json.loads(json.dumps(payload)), payload)


if __name__ == "__main__":
    unittest.main()
