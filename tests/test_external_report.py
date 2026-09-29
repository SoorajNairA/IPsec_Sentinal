from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from ipsec_sentinel.external.registry import ExternalDatasetRegistry
from ipsec_sentinel.external.report import build_external_report, write_external_report
from ipsec_sentinel.external.storage import ExternalPaths


REGISTRY = ExternalDatasetRegistry.load(Path("metadata/external-datasets.yaml"))


class ExternalReportTest(unittest.TestCase):
    def test_report_reconciles_registry_receipts_inventories_and_disk_usage(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = ExternalPaths.create(Path(temporary))
            artifact = REGISTRY.source("usbvpn2022").artifacts[0]
            directory = paths.downloads / artifact.artifact_id
            directory.mkdir()
            (directory / artifact.filename).write_bytes(b"abc")
            (directory / f"{artifact.filename}.receipt.json").write_text(
                json.dumps({"observed_size_bytes": 3, "outcome": "downloaded"}),
                encoding="utf-8",
            )
            inventory = paths.inventories / "usbvpn2022" / "digest"
            inventory.mkdir(parents=True)
            (inventory / "inspection.json").write_text(
                json.dumps({
                    "compatible": False,
                    "compatibility_reasons": ["x"],
                    "structure": [{"sample_values": ["public-row"]}],
                }),
                encoding="utf-8",
            )

            payload = build_external_report(REGISTRY, paths).to_dict()

        usb = next(item for item in payload["sources"]
                   if item["source_id"] == "usbvpn2022")
        self.assertEqual(usb["artifacts"][0]["receipt"]["observed_size_bytes"], 3)
        self.assertEqual(usb["inventory"]["compatibility_reasons"], ["x"])
        self.assertNotIn("structure", usb["inventory"])
        self.assertGreaterEqual(payload["disk_usage_bytes"], 3)

    def test_report_lists_protocols_classes_mappings_licenses_and_compatibility(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = build_external_report(
                REGISTRY, ExternalPaths.create(Path(temporary))
            ).to_dict()
        usb = next(item for item in report["sources"]
                   if item["source_id"] == "usbvpn2022")
        self.assertIn("l2tp_ipsec_natt", usb["observed_protocols"])
        self.assertEqual(usb["label_mappings"]["mail"], "email")
        self.assertEqual(usb["license"]["redistribution_status"], "allowed")
        self.assertEqual(usb["inspection_state"], "incompatible")

    def test_report_names_every_intentionally_omitted_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = build_external_report(
                REGISTRY, ExternalPaths.create(Path(temporary))
            ).to_dict()
        omitted = {item["artifact"] for item in report["intentionally_omitted"]}
        self.assertEqual(omitted, {"VNAT raw PCAP archive", "ISCXVPN2016 full collection"})

    def test_report_never_embeds_public_rows_or_paths_as_features(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = ExternalPaths.create(Path(temporary))
            report = build_external_report(REGISTRY, paths)
            written = write_external_report(report, paths)
            text = written["json"].read_text(encoding="utf-8")
        for forbidden in (
            '"features"', '"observations"', '"parent_session_id"',
            '"absolute_timestamp"', str(paths.root),
        ):
            self.assertNotIn(forbidden, text)

    def test_iscx_remains_metadata_only_without_download_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = build_external_report(
                REGISTRY, ExternalPaths.create(Path(temporary))
            ).to_dict()
        iscx = next(item for item in report["sources"]
                    if item["source_id"] == "iscxvpn2016")
        self.assertEqual(iscx["acquisition_state"], "metadata_only")
        self.assertEqual(iscx["artifacts"], [])


if __name__ == "__main__":
    unittest.main()
