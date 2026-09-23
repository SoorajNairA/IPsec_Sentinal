from pathlib import Path
from tempfile import TemporaryDirectory
import json
import os
import subprocess
import unittest

from ipsec_sentinel.artifacts import REQUIRED_SUCCESS_FILES
from ipsec_sentinel.runner import run_secure_baseline


@unittest.skipUnless(
    os.environ.get("IPSEC_SENTINEL_INTEGRATION") == "1",
    "set IPSEC_SENTINEL_INTEGRATION=1 and run as root",
)
class SecureBaselineIntegrationTest(unittest.TestCase):
    def test_real_tunnel_produces_passing_artifacts_and_cleans_up(self) -> None:
        with TemporaryDirectory(prefix="ipsec-sentinel-integration-", dir="/tmp") as directory:
            runs_root = Path(directory)
            exit_code = run_secure_baseline("secure-baseline", runs_root=runs_root)

            self.assertEqual(exit_code, 0)
            run_dirs = list(runs_root.iterdir())
            self.assertEqual(len(run_dirs), 1)
            run_dir = run_dirs[0]
            self.assertTrue(
                REQUIRED_SUCCESS_FILES.issubset({path.name for path in run_dir.iterdir()})
            )
            self.assertEqual(
                json.loads((run_dir / "verification.json").read_text())["status"],
                "PASS",
            )
            self.assertEqual(
                json.loads((run_dir / "ground_truth.json").read_text())["status"],
                "PASS",
            )
            namespaces = subprocess.run(
                ["ip", "netns", "list"],
                check=True,
                capture_output=True,
                text=True,
                timeout=5,
            ).stdout
            self.assertNotIn("ips-gwa", namespaces)


if __name__ == "__main__":
    unittest.main()
