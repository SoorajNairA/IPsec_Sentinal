from pathlib import Path
import unittest

from ipsec_sentinel.evidence import (
    evaluate_baseline,
    evaluate_pfs,
    parse_ping,
    parse_sa,
    parse_xfrm,
)
from ipsec_sentinel.models import CaptureEvidence


FIXTURES = Path(__file__).parent / "fixtures"
PING = "5 packets transmitted, 5 received, 0% packet loss"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text()


def baseline_inputs():
    sas = {
        "gateway-a": fixture("swanctl-gateway-a.txt"),
        "gateway-b": fixture("swanctl-gateway-b.txt"),
    }
    xfrm = {
        "gateway-a": fixture("xfrm-gateway-a.txt"),
        "gateway-b": fixture("xfrm-gateway-b.txt"),
    }
    capture = CaptureEvidence("encrypted.pcap", 14, 4, 10, 0, 0)
    return sas, xfrm, PING, capture


class EvidenceParsingTest(unittest.TestCase):
    def test_pfs_is_not_tested_by_initial_child_establishment(self) -> None:
        sas, _, _, _ = baseline_inputs()

        observation = evaluate_pfs(sas, None, "", attempted=False)

        self.assertEqual(observation.status, "NOT_TESTED")
        self.assertFalse(observation.rekey_observed)

    def test_pfs_requires_changed_spis_and_fresh_dh_selection(self) -> None:
        before, _, _, _ = baseline_inputs()
        after = {
            gateway: text.replace("c2ad5304", "a1a2a3a4").replace("cbecd5e6", "b1b2b3b4")
            for gateway, text in before.items()
        }
        log = "selected proposal: ESP:AES_GCM_16_256/ECP_384/NO_EXT_SEQ\n"

        verified = evaluate_pfs(before, after, log, attempted=True)
        no_dh = evaluate_pfs(before, after, "selected proposal: ESP:AES_GCM_16_256/NO_EXT_SEQ", attempted=True)
        unchanged = evaluate_pfs(before, before, log, attempted=True)

        self.assertEqual(verified.status, "VERIFIED")
        self.assertTrue(verified.rekey_observed)
        self.assertEqual(no_dh.status, "NOT_VERIFIED")
        self.assertEqual(unchanged.status, "NOT_VERIFIED")

        one_sided = {
            gateway: text.replace("c2ad5304", "a1a2a3a4")
            for gateway, text in before.items()
        }
        incomplete = evaluate_pfs(
            before, after, log, attempted=True, completed=False
        )
        self.assertEqual(
            evaluate_pfs(before, one_sided, log, attempted=True).status,
            "NOT_VERIFIED",
        )
        self.assertEqual(incomplete.status, "NOT_VERIFIED")

    def test_parser_uses_new_installed_child_while_old_child_is_deleted(self) -> None:
        text = (
            "state=ESTABLISHED child-sas {"
            "protected-nets-1 {name=protected-nets state=DELETED spi-in=11111111 spi-out=22222222} "
            "protected-nets-2 {name=protected-nets state=INSTALLED spi-in=33333333 spi-out=44444444}"
            "}}"
        )

        parsed = parse_sa(text)

        self.assertEqual(parsed.child_state, "INSTALLED")
        self.assertEqual(parsed.spis, ("33333333", "44444444"))

    def test_parses_required_sa_xfrm_and_ping_fields(self) -> None:
        sa = parse_sa(fixture("swanctl-gateway-a.txt"))
        xfrm = parse_xfrm(fixture("xfrm-gateway-a.txt"))
        ping = parse_ping(PING)

        self.assertEqual(sa.ike_state, "ESTABLISHED")
        self.assertEqual(sa.child_state, "INSTALLED")
        self.assertEqual(sa.ike_proposal, "AES_GCM_16_256/PRF_HMAC_SHA2_384/ECP_384")
        self.assertEqual(sa.esp_proposal, "AES_GCM_16_256")
        self.assertEqual(sa.local_id, "gateway-a")
        self.assertEqual(sa.remote_id, "gateway-b")
        self.assertEqual(sa.local_ts, "10.10.0.0/24")
        self.assertEqual(sa.remote_ts, "10.20.0.0/24")
        self.assertEqual(sa.spis, ("c2ad5304", "cbecd5e6"))
        self.assertTrue(xfrm.state_valid)
        self.assertTrue(xfrm.policy_valid)
        self.assertEqual((ping.sent, ping.received, ping.success), (5, 5, True))

    def test_baseline_passes_only_when_every_source_agrees(self) -> None:
        verification = evaluate_baseline(*baseline_inputs(), run_id="run-1")
        self.assertEqual(verification.status, "PASS")
        self.assertTrue(all(check.passed for check in verification.checks))

    def test_each_independent_evidence_failure_fails_the_verdict(self) -> None:
        mutations = (
            ("ike.gateway-a.established", "ESTABLISHED", "CONNECTING", "sas", "gateway-a"),
            ("child.gateway-a.installed", "state=INSTALLED", "state=REKEYING", "sas", "gateway-a"),
            ("selectors.gateway-a", "10.10.0.0/24", "10.99.0.0/24", "sas", "gateway-a"),
            ("xfrm.state.gateway-a", "mode tunnel", "mode transport", "xfrm", "gateway-a"),
            ("xfrm.policy.gateway-a", "10.10.0.0/24", "10.99.0.0/24", "xfrm", "gateway-a"),
        )
        for check_name, old, new, group, gateway in mutations:
            with self.subTest(check=check_name):
                sas, xfrm, ping, capture = baseline_inputs()
                target = sas if group == "sas" else xfrm
                target[gateway] = target[gateway].replace(old, new, 1)
                result = evaluate_baseline(sas, xfrm, ping, capture)
                checks = {check.name: check.passed for check in result.checks}
                self.assertEqual(result.status, "FAIL")
                self.assertFalse(checks[check_name])

    def test_ping_ike_capture_and_esp_capture_are_conjunctive(self) -> None:
        cases = (
            ("traffic.icmp", "ping", "5 packets transmitted, 0 received, 100% packet loss"),
            ("capture.ike", "ike", 0),
            ("capture.esp", "esp", 0),
        )
        for check_name, kind, value in cases:
            with self.subTest(check=check_name):
                sas, xfrm, ping, capture = baseline_inputs()
                if kind == "ping":
                    ping = value
                elif kind == "ike":
                    capture = CaptureEvidence("encrypted.pcap", 10, value, 10, 0, 0)
                else:
                    capture = CaptureEvidence("encrypted.pcap", 4, 4, value, 0, 0)
                result = evaluate_baseline(sas, xfrm, ping, capture)
                checks = {check.name: check.passed for check in result.checks}
                self.assertEqual(result.status, "FAIL")
                self.assertFalse(checks[check_name])

    def test_xfrm_spis_must_match_reciprocal_child_sa_spis(self) -> None:
        sas, xfrm, ping, capture = baseline_inputs()
        xfrm["gateway-a"] = xfrm["gateway-a"].replace("0xcbecd5e6", "0xdeadbeef")

        result = evaluate_baseline(sas, xfrm, ping, capture)
        checks = {check.name: check.passed for check in result.checks}

        self.assertEqual(result.status, "FAIL")
        self.assertFalse(checks["xfrm.state.gateway-a"])

        sas, xfrm, ping, capture = baseline_inputs()
        sas["gateway-b"] = sas["gateway-b"].replace("spi-out=c2ad5304", "spi-out=deadbeef")
        result = evaluate_baseline(sas, xfrm, ping, capture)
        checks = {check.name: check.passed for check in result.checks}
        self.assertEqual(result.status, "FAIL")
        self.assertFalse(checks["child.spis.reciprocal"])


if __name__ == "__main__":
    unittest.main()
