from __future__ import annotations

import unittest

from ipsec_sentinel.external.models import (
    EXTERNAL_OBSERVATION_SCHEMA_VERSION,
    ExternalPacketObservation,
)
from ipsec_sentinel.ml.features import extract_session_features
from ipsec_sentinel.ml.observations import PacketObservation
from ipsec_sentinel.ml.schema import FEATURE_NAMES
from ipsec_sentinel.pcap import EspPacket


class ExternalFeatureCompatibilityTest(unittest.TestCase):
    def test_external_and_native_observations_with_same_behavior_have_identical_features(self):
        native = (
            EspPacket(1_000_000_000, 0.0, 128, "forward"),
            EspPacket(1_250_000_000, 0.25, 256, "reverse"),
        )
        external = tuple(
            ExternalPacketObservation(
                EXTERNAL_OBSERVATION_SCHEMA_VERSION,
                "vnat/session-7",
                index,
                time_us,
                size,
                direction,
                "messaging",
                "mit_ll_vnat",
                "vpn_unspecified",
            )
            for index, (time_us, size, direction) in enumerate(
                ((0, 128, "forward"), (250_000, 256, "reverse"))
            )
        )

        self.assertEqual(extract_session_features(external), extract_session_features(native))

    def test_provenance_label_protocol_filename_and_parent_id_are_absent_from_feature_schema(self):
        forbidden = {"source_dataset", "vpn_protocol", "filename", "parent_session_id", "label"}
        self.assertTrue(forbidden.isdisjoint(FEATURE_NAMES))

    def test_external_model_exposes_only_time_size_direction_to_calculator(self):
        packet = ExternalPacketObservation(
            EXTERNAL_OBSERVATION_SCHEMA_VERSION,
            "source/session",
            0,
            125_000,
            512,
            "forward",
            "web",
            "source",
            "openvpn",
        )
        self.assertIsInstance(packet, PacketObservation)
        self.assertEqual(packet.relative_time_seconds, 0.125)
        self.assertEqual(packet.length, 512)


if __name__ == "__main__":
    unittest.main()
