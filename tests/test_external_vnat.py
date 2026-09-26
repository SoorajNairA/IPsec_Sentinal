from __future__ import annotations

from pathlib import Path
import unittest

from ipsec_sentinel.external.registry import ExternalDatasetRegistry, InspectionState


class VnatEvidenceGateTest(unittest.TestCase):
    def test_vnat_registry_marks_adapter_unavailable_with_inspection_reasons(self):
        source = ExternalDatasetRegistry.load(
            Path("metadata/external-datasets.yaml")
        ).source("mit_ll_vnat")

        self.assertEqual(source.inspection.state, InspectionState.INCOMPATIBLE)
        self.assertIsNone(source.inspection.adapter_id)
        joined = " ".join(source.inspection.notes).casefold()
        self.assertIn("objectatom", joined)
        self.assertIn("bounded", joined)
        self.assertIn("7.4 gib", joined)


if __name__ == "__main__":
    unittest.main()
