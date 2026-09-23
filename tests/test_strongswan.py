from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock
import unittest

from ipsec_sentinel.strongswan import GatewayFiles, StrongSwanPair


class StrongSwanRenderingTest(unittest.TestCase):
    def test_rekey_snapshots_spis_and_returns_only_new_log_segment(self) -> None:
        before = {
            "gateway-a": "state=INSTALLED spi-in=11111111 spi-out=22222222",
            "gateway-b": "state=INSTALLED spi-in=22222222 spi-out=11111111",
        }
        after = {
            "gateway-a": "state=INSTALLED spi-in=33333333 spi-out=44444444",
            "gateway-b": "state=INSTALLED spi-in=44444444 spi-out=33333333",
        }
        with TemporaryDirectory() as directory:
            root = Path(directory)
            charon_log = root / "charon.log"
            charon_log.write_text("initial establishment\n")
            pair = StrongSwanPair(StringIO(), timeout=0.5)
            pair.files = {
                name: GatewayFiles(
                    name,
                    "ips-gwa" if name == "gateway-a" else "ips-gwb",
                    root / name / "strongswan.conf",
                    root / name / "swanctl.conf",
                    root / name / "charon.vici",
                    root / name / "charon.pid",
                    charon_log,
                )
                for name in ("gateway-a", "gateway-b")
            }
            pair.list_sas = Mock(side_effect=[before, after])

            def rekey_command(*_args):
                with charon_log.open("a") as output:
                    output.write("selected proposal: ESP:AES_GCM_16_256/ECP_384/NO_EXT_SEQ\n")
                return Mock(stdout="rekey completed")

            pair._swanctl = Mock(side_effect=rekey_command)

            result = pair.rekey()

            self.assertEqual(result.before_sas, before)
            self.assertEqual(result.after_sas, after)
            self.assertNotIn("initial establishment", result.log_segment)
            self.assertIn("ECP_384", result.log_segment)
            pair._swanctl.assert_called_once_with(
                "gateway-a", "--rekey", "--child", "protected-nets"
            )

    def test_renders_isolated_reversed_gateway_configurations(self) -> None:
        with TemporaryDirectory() as directory:
            pair = StrongSwanPair(StringIO())
            rendered = pair.render_configs(Path(directory), runtime_root=Path("/run/test-run"))

            a_strong = rendered["gateway-a"].strongswan.read_text()
            b_strong = rendered["gateway-b"].strongswan.read_text()
            a_swan = rendered["gateway-a"].swanctl.read_text()
            b_swan = rendered["gateway-b"].swanctl.read_text()

            self.assertIn("/run/test-run/gateway-a/charon.vici", a_strong)
            self.assertIn("/run/test-run/gateway-b/charon.vici", b_strong)
            self.assertNotEqual(rendered["gateway-a"].vici_uri, rendered["gateway-b"].vici_uri)
            self.assertNotEqual(rendered["gateway-a"].pid, rendered["gateway-b"].pid)
            self.assertNotEqual(rendered["gateway-a"].log, rendered["gateway-b"].log)

            self.assertIn("local_addrs = 192.0.2.1", a_swan)
            self.assertIn("remote_addrs = 192.0.2.2", a_swan)
            self.assertIn("local_ts = 10.10.0.0/24", a_swan)
            self.assertIn("remote_ts = 10.20.0.0/24", a_swan)
            self.assertIn("local_addrs = 192.0.2.2", b_swan)
            self.assertIn("remote_addrs = 192.0.2.1", b_swan)
            self.assertIn("local_ts = 10.20.0.0/24", b_swan)
            self.assertIn("remote_ts = 10.10.0.0/24", b_swan)

            for text in (a_swan, b_swan):
                self.assertIn("proposals = aes256gcm16-prfsha384-ecp384", text)
                self.assertIn("esp_proposals = aes256gcm16-ecp384", text)
                self.assertIn("mobike = no", text)
                self.assertIn("encap = no", text)
                self.assertNotIn("/etc/swanctl", text)


if __name__ == "__main__":
    unittest.main()
