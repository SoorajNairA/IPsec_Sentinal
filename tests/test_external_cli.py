from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ipsec_sentinel.external.acquire import AcquisitionError
from ipsec_sentinel.external.cli import (
    EXIT_ACQUISITION,
    EXIT_CHECKSUM,
    EXIT_CONFIG,
    EXIT_INCOMPATIBLE,
    EXIT_INSPECTION,
    build_parser,
    main,
)
from ipsec_sentinel.external.inspect import ArchiveSafetyError


class ExternalCliTest(unittest.TestCase):
    def test_registry_validate_is_read_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "must-not-exist"
            output = StringIO()
            with patch.dict(
                "os.environ", {"IPSEC_SENTINEL_EXTERNAL_DATA_ROOT": str(root)}, clear=False
            ), redirect_stdout(output):
                code = main(["registry", "validate"])

            self.assertEqual(code, 0)
            self.assertFalse(root.exists())
            self.assertEqual(json.loads(output.getvalue())["sources"], 4)

    def test_acquire_accepts_only_registry_source_and_phase_allowlist(self):
        parser = build_parser()
        args = parser.parse_args(["acquire", "usbvpn2022", "--resume"])
        self.assertEqual(args.source_id, "usbvpn2022")
        self.assertTrue(args.resume)
        self.assertNotIn("url", vars(args))
        self.assertNotIn("output", vars(args))

        with redirect_stdout(StringIO()):
            self.assertEqual(main(["acquire", "iscxvpn2016"]), EXIT_CONFIG)
            self.assertEqual(main(["acquire", "does-not-exist"]), EXIT_CONFIG)

    def test_every_mutating_command_prints_resolved_root_and_byte_scale(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "external"
            output = StringIO()
            with patch.dict(
                "os.environ", {"IPSEC_SENTINEL_EXTERNAL_DATA_ROOT": str(root)}, clear=False
            ), patch(
                "ipsec_sentinel.external.cli.acquire_artifact",
                side_effect=AcquisitionError("transport", "fixture stop after preamble"),
            ), redirect_stdout(output):
                code = main(["acquire", "usbvpn2022"])

            lines = [json.loads(line) for line in output.getvalue().splitlines()]
            self.assertEqual(code, EXIT_ACQUISITION)
            self.assertEqual(lines[0]["external_root"], str(root.resolve()))
            self.assertEqual(lines[0]["declared_bytes"], 811_738_498)

    def test_normalize_defaults_to_bounded_sample_and_requires_compatible_inspection(self):
        parser = build_parser()
        bounded = parser.parse_args(["normalize", "mit_ll_vnat"])
        self.assertEqual(bounded.sample_sessions, 10)
        self.assertFalse(bounded.all_sessions)
        unbounded = parser.parse_args(["normalize", "mit_ll_vnat", "--all-sessions"])
        self.assertTrue(unbounded.all_sessions)

        with tempfile.TemporaryDirectory() as temporary, patch.dict(
            "os.environ",
            {"IPSEC_SENTINEL_EXTERNAL_DATA_ROOT": str(Path(temporary) / "external")},
            clear=False,
        ), redirect_stdout(StringIO()):
            self.assertEqual(main(["normalize", "mit_ll_vnat"]), EXIT_INCOMPATIBLE)

    def test_exit_codes_distinguish_config_acquire_checksum_inspection_and_incompatibility(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = str(Path(temporary) / "external")
            environment = {"IPSEC_SENTINEL_EXTERNAL_DATA_ROOT": root}
            with patch.dict("os.environ", environment, clear=False), redirect_stdout(StringIO()):
                with patch(
                    "ipsec_sentinel.external.cli.acquire_artifact",
                    side_effect=AcquisitionError("transport", "offline"),
                ):
                    self.assertEqual(main(["acquire", "usbvpn2022"]), EXIT_ACQUISITION)
                with patch(
                    "ipsec_sentinel.external.cli.acquire_artifact",
                    side_effect=AcquisitionError("checksum", "bad"),
                ):
                    self.assertEqual(main(["acquire", "usbvpn2022"]), EXIT_CHECKSUM)
                with patch(
                    "ipsec_sentinel.external.cli._inspect_source",
                    side_effect=ArchiveSafetyError("unsafe"),
                ):
                    self.assertEqual(main(["inspect", "usbvpn2022"]), EXIT_INSPECTION)
                self.assertEqual(main(["acquire", "iscxvpn2016"]), EXIT_CONFIG)
                self.assertEqual(main(["normalize", "mit_ll_vnat"]), EXIT_INCOMPATIBLE)


if __name__ == "__main__":
    unittest.main()
