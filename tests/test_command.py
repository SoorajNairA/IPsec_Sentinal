from io import StringIO
from time import monotonic
import sys
import unittest

from ipsec_sentinel.command import CommandFailure, run_checked


class CommandTest(unittest.TestCase):
    def test_returns_and_logs_real_stdout_and_stderr(self) -> None:
        log = StringIO()

        result = run_checked(
            [
                sys.executable,
                "-c",
                "import sys; print('ready'); print('warning', file=sys.stderr)",
            ],
            timeout=2,
            log=log,
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "ready\n")
        self.assertEqual(result.stderr, "warning\n")
        self.assertIn("ready", log.getvalue())
        self.assertIn("warning", log.getvalue())

    def test_nonzero_exit_raises_with_command_context(self) -> None:
        log = StringIO()

        with self.assertRaises(CommandFailure) as raised:
            run_checked(
                [
                    sys.executable,
                    "-c",
                    "import sys; print('broken', file=sys.stderr); sys.exit(7)",
                ],
                timeout=2,
                log=log,
            )

        error = raised.exception
        self.assertEqual(error.returncode, 7)
        self.assertFalse(error.timed_out)
        self.assertIn("broken", error.stderr)
        self.assertIn("sys.exit(7)", str(error))
        self.assertIn("exit 7", str(error))

    def test_timeout_kills_the_child_within_the_bound(self) -> None:
        log = StringIO()
        started = monotonic()

        with self.assertRaises(CommandFailure) as raised:
            run_checked(
                [sys.executable, "-c", "import time; time.sleep(5)"],
                timeout=0.1,
                log=log,
            )

        elapsed = monotonic() - started
        self.assertTrue(raised.exception.timed_out)
        self.assertIsNone(raised.exception.returncode)
        self.assertLess(elapsed, 1.5)
        self.assertIn("timed out", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
