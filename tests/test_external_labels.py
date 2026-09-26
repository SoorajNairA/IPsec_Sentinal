from __future__ import annotations

from pathlib import Path
import unittest

from ipsec_sentinel.external.labels import map_external_label
from ipsec_sentinel.external.registry import ExternalDatasetRegistry


REGISTRY = ExternalDatasetRegistry.load(Path("metadata/external-datasets.yaml"))


class ExternalLabelTest(unittest.TestCase):
    def test_explicit_mappings_cover_only_streaming_voip_chat_file_web_email(self):
        expected = {
            ("mit_ll_vnat", "Streaming"): "video",
            ("mit_ll_vnat", "VoIP"): "voip",
            ("mit_ll_vnat", "Chat"): "messaging",
            ("mit_ll_vnat", "File Transfer"): "file_transfer",
            ("iscxvpn2016", "Web Browsing"): "web",
            ("iscxvpn2016", "Email"): "email",
        }
        for (source, original), canonical in expected.items():
            with self.subTest(source=source, original=original):
                decision = map_external_label(source, original, REGISTRY)
                self.assertEqual(decision.status, "mapped_supervised")
                self.assertEqual(decision.canonical_label, canonical)
                self.assertTrue(decision.known_training_class)

    def test_p2p_ssh_rdp_c2_mixed_and_unknown_remain_unmapped(self):
        for original in ("P2P", "SSH", "RDP", "C2", "mixed", "unknown terminal traffic"):
            with self.subTest(original=original):
                decision = map_external_label("mit_ll_vnat", original, REGISTRY)
                self.assertIsNone(decision.canonical_label)
                self.assertFalse(decision.known_training_class)
                self.assertIn(decision.status, ("unmapped", "ood_candidate"))

    def test_mapping_requires_exact_per_source_entry_not_substring_match(self):
        for source, original in (
            ("mit_ll_vnat", "streaming"),
            ("mit_ll_vnat", "Streaming extra"),
            ("usbvpn2022", "Streaming"),
            ("mit_ll_vnat", "ICMP"),
        ):
            with self.subTest(source=source, original=original):
                decision = map_external_label(source, original, REGISTRY)
                self.assertIsNone(decision.canonical_label)
                self.assertFalse(decision.known_training_class)


if __name__ == "__main__":
    unittest.main()
