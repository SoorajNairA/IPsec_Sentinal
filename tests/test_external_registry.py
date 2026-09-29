from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

import yaml

from ipsec_sentinel.external.registry import (
    AcquisitionState,
    ExternalDatasetRegistry,
    InspectionState,
    RedistributionStatus,
)


REGISTRY = Path("metadata/external-datasets.yaml")


class ExternalRegistryTest(unittest.TestCase):
    def test_loads_four_sources_with_separate_publisher_and_local_facts(self):
        registry = ExternalDatasetRegistry.load(REGISTRY)

        self.assertEqual(
            tuple(source.source_id for source in registry.sources),
            (
                "usbvpn2022",
                "vpn_protocol_performance_2026",
                "mit_ll_vnat",
                "iscxvpn2016",
            ),
        )
        usb = registry.source("usbvpn2022")
        self.assertEqual(usb.doi, "10.5281/zenodo.7301756")
        self.assertEqual(usb.artifacts[0].published_size_bytes, 811_738_498)
        self.assertEqual(
            (usb.artifacts[0].publisher_checksum.algorithm,
             usb.artifacts[0].publisher_checksum.value),
            ("md5", "35a4aef78526440cd6e352de49c4daf2"),
        )
        self.assertEqual(
            usb.artifacts[0].local_verification.sha256,
            "8039945ffa3f22ff9443787dfbeaf74fd89d33cddd292dcaa6f7cc4b9fe2f54e",
        )
        self.assertEqual(usb.artifacts[0].local_verification.result, "verified")

        strongswan = registry.source("vpn_protocol_performance_2026")
        self.assertEqual(strongswan.doi, "10.5281/zenodo.21645499")
        self.assertEqual(strongswan.artifacts[0].published_size_bytes, 4_701_066)
        self.assertEqual(
            strongswan.artifacts[0].publisher_checksum.value,
            "bca99ce9a6ad9a3e2ad03c9f0b63db48",
        )

        vnat = registry.source("mit_ll_vnat")
        self.assertEqual(vnat.artifacts[0].published_size_bytes, 1_045_436_008)
        self.assertIsNone(vnat.artifacts[0].publisher_checksum)

        iscx = registry.source("iscxvpn2016")
        self.assertEqual(iscx.acquisition_state, AcquisitionState.METADATA_ONLY)

    def test_rejects_duplicate_ids_unknown_fields_and_malformed_checksums(self):
        payload = yaml.safe_load(REGISTRY.read_text(encoding="utf-8"))
        cases = []

        duplicate = dict(payload)
        duplicate["sources"] = [*payload["sources"], payload["sources"][0]]
        cases.append(duplicate)

        unknown = yaml.safe_load(REGISTRY.read_text(encoding="utf-8"))
        unknown["sources"][0]["surprise"] = True
        cases.append(unknown)

        malformed = yaml.safe_load(REGISTRY.read_text(encoding="utf-8"))
        malformed["sources"][0]["artifacts"][0]["publisher_checksum"] = {
            "algorithm": "sha1",
            "value": "abc",
        }
        cases.append(malformed)

        for index, candidate in enumerate(cases):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "registry.yaml"
                path.write_text(yaml.safe_dump(candidate), encoding="utf-8")
                with self.assertRaises(ValueError):
                    ExternalDatasetRegistry.load(path)

    def test_requires_license_evidence_and_explicit_redistribution_state(self):
        registry = ExternalDatasetRegistry.load(REGISTRY)
        self.assertEqual(
            registry.source("usbvpn2022").license.redistribution_status,
            RedistributionStatus.ALLOWED,
        )
        self.assertEqual(
            registry.source("iscxvpn2016").license.redistribution_status,
            RedistributionStatus.UNKNOWN,
        )
        for source in registry.sources:
            self.assertTrue(source.license.evidence_url.startswith("https://"))

        payload = yaml.safe_load(REGISTRY.read_text(encoding="utf-8"))
        del payload["sources"][0]["license"]["evidence_url"]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "registry.yaml"
            path.write_text(yaml.safe_dump(payload), encoding="utf-8")
            with self.assertRaises(ValueError):
                ExternalDatasetRegistry.load(path)

    def test_registry_records_evidence_gated_usb_and_vnat_schemas(self):
        registry = ExternalDatasetRegistry.load(REGISTRY)
        usb = registry.source("usbvpn2022")
        self.assertEqual(usb.inspection.state, InspectionState.INCOMPATIBLE)
        self.assertEqual(usb.inspection.observed_formats, ("zip", "json"))
        self.assertEqual(usb.inspection.observed_protocols, ("l2tp_ipsec_natt",))
        self.assertEqual(
            usb.inspection.observed_labels,
            ("mail", "meet", "non_streaming", "ssh", "streaming"),
        )
        self.assertIsNone(usb.inspection.adapter_id)

        vnat = registry.source("mit_ll_vnat")
        self.assertEqual(vnat.inspection.state, InspectionState.INCOMPATIBLE)
        self.assertEqual(vnat.inspection.observed_formats, ("hdf5", "pandas_fixed"))
        self.assertEqual(vnat.inspection.observed_protocols, ("vpn_unspecified", "non_vpn"))
        self.assertEqual(
            vnat.inspection.observed_labels,
            ("Streaming", "VoIP", "Chat", "C2", "File Transfer"),
        )
        self.assertIsNone(vnat.inspection.adapter_id)


if __name__ == "__main__":
    unittest.main()
