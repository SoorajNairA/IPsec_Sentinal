from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from ipsec_sentinel.scenario import Scenario, ScenarioError


VALID_SCENARIO = """\
id: secure-baseline
ipsec:
  ike_version: 2
  mode: tunnel
  ike_proposal: aes256gcm16-prfsha384-ecp384
  esp_proposal: aes256gcm16-ecp384
  local_subnet: 10.10.0.0/24
  remote_subnet: 10.20.0.0/24
  transit_subnet: 192.0.2.0/30
  pfs: true
  ip_version: 4
traffic:
  type: icmp
  count: 5
capture:
  enabled: true
"""


class ScenarioTest(unittest.TestCase):
    def load_text(self, text: str) -> Scenario:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "scenario.yaml"
            path.write_text(text, encoding="utf-8")
            return Scenario.load(path)

    def test_loads_the_exact_secure_baseline_contract(self) -> None:
        scenario = self.load_text(VALID_SCENARIO)

        self.assertEqual(scenario.id, "secure-baseline")
        self.assertEqual(scenario.ipsec.ike_version, 2)
        self.assertEqual(scenario.ipsec.mode, "tunnel")
        self.assertEqual(
            scenario.ipsec.ike_proposal,
            "aes256gcm16-prfsha384-ecp384",
        )
        self.assertEqual(scenario.ipsec.esp_proposal, "aes256gcm16-ecp384")
        self.assertEqual(scenario.ipsec.local_subnet, "10.10.0.0/24")
        self.assertEqual(scenario.ipsec.remote_subnet, "10.20.0.0/24")
        self.assertEqual(scenario.ipsec.transit_subnet, "192.0.2.0/30")
        self.assertTrue(scenario.ipsec.pfs)
        self.assertEqual(scenario.ipsec.ip_version, 4)
        self.assertEqual(scenario.traffic.type, "icmp")
        self.assertEqual(scenario.traffic.count, 5)
        self.assertTrue(scenario.capture.enabled)

    def test_rejects_an_unknown_top_level_field(self) -> None:
        invalid = VALID_SCENARIO + "future_matrix: true\n"

        with self.assertRaisesRegex(ScenarioError, "future_matrix"):
            self.load_text(invalid)

    def test_rejects_ikev1(self) -> None:
        invalid = VALID_SCENARIO.replace("ike_version: 2", "ike_version: 1")

        with self.assertRaisesRegex(ScenarioError, "ike_version"):
            self.load_text(invalid)

    def test_rejects_transport_mode(self) -> None:
        invalid = VALID_SCENARIO.replace("mode: tunnel", "mode: transport")

        with self.assertRaisesRegex(ScenarioError, "mode"):
            self.load_text(invalid)

    def test_rejects_altered_phase_one_networks(self) -> None:
        cases = (
            ("10.10.0.0/24", "10.11.0.0/24", "local_subnet"),
            ("10.20.0.0/24", "10.21.0.0/24", "remote_subnet"),
            ("192.0.2.0/30", "192.0.2.0/29", "transit_subnet"),
        )
        for original, replacement, field in cases:
            with self.subTest(field=field):
                invalid = VALID_SCENARIO.replace(original, replacement)
                with self.assertRaisesRegex(ScenarioError, field):
                    self.load_text(invalid)


if __name__ == "__main__":
    unittest.main()
