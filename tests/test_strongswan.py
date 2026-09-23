from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from ipsec_sentinel.strongswan import StrongSwanPair


class StrongSwanRenderingTest(unittest.TestCase):
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
