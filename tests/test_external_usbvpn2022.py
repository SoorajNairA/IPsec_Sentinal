from __future__ import annotations

from pathlib import Path
import unittest

from ipsec_sentinel.external.registry import (
    ExternalDatasetRegistry,
    InspectionState,
)


class UsbVpn2022EvidenceGateTest(unittest.TestCase):
    def test_usb_registry_marks_adapter_unavailable_with_inspection_reasons(self):
        source = ExternalDatasetRegistry.load(
            Path("metadata/external-datasets.yaml")
        ).source("usbvpn2022")

        self.assertEqual(source.inspection.state, InspectionState.INCOMPATIBLE)
        self.assertIsNone(source.inspection.adapter_id)
        joined = " ".join(source.inspection.notes).casefold()
        self.assertIn("aggregate", joined)
        self.assertIn("individual", joined)
        self.assertIn("icmp", joined)


if __name__ == "__main__":
    unittest.main()
