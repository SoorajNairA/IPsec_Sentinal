from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from ipsec_sentinel.live.observations import (
    EspTotals,
    StrongSwanObservationParser,
    summarize_esp,
)


FIXTURES = Path(__file__).parent / "fixtures"


class StrongSwanObservationParserTest(unittest.TestCase):
    def test_genuine_initiator_log_lines_produce_evidence_events(self) -> None:
        parser = StrongSwanObservationParser()
        lines = (
            "08[ENC] <secure-baseline|1> generating IKE_SA_INIT request 0 [ SA KE No ]",
            "14[ENC] <secure-baseline|1> parsed IKE_SA_INIT response 0 [ SA KE No ]",
            "14[CFG] <secure-baseline|1> selected proposal: IKE:AES_GCM_16_256/PRF_HMAC_SHA2_384/ECP_384",
            "14[ENC] <secure-baseline|1> generating IKE_AUTH request 1 [ IDi AUTH SA TSi TSr ]",
            "11[ENC] <secure-baseline|1> parsed IKE_AUTH response 1 [ IDr AUTH SA TSi TSr ]",
            "11[IKE] <secure-baseline|1> IKE_SA secure-baseline[1] established between 192.0.2.1[gateway-a]...192.0.2.2[gateway-b]",
            "11[IKE] <secure-baseline|1> CHILD_SA protected-nets{1} established with SPIs c8be46f5_i c8ec6a73_o and TS 10.10.0.0/24 === 10.20.0.0/24",
        )

        observations = [parser.feed(line) for line in lines]

        self.assertEqual(
            [item.type for item in observations if item is not None],
            [
                "ike.sa_init.request",
                "ike.sa_init.response",
                "ike.proposal.selected",
                "ike.auth.request",
                "ike.auth.response",
                "ike.sa.established",
                "child_sa.established",
            ],
        )
        proposal = observations[2]
        self.assertIsNotNone(proposal)
        self.assertEqual(
            proposal.data,  # type: ignore[union-attr]
            {
                "raw": "IKE:AES_GCM_16_256/PRF_HMAC_SHA2_384/ECP_384",
                "encryption": "AES_GCM_16_256",
                "prf": "PRF_HMAC_SHA2_384",
                "dh_group": "ECP_384",
            },
        )
        child = observations[-1]
        self.assertEqual(child.data["inbound_spi"], "0xc8be46f5")  # type: ignore[union-attr]
        self.assertEqual(child.data["outbound_spi"], "0xc8ec6a73")  # type: ignore[union-attr]

    def test_unrecognized_or_repeated_lines_do_not_fabricate_progress(self) -> None:
        parser = StrongSwanObservationParser()
        line = "14[CFG] looking for peer configs matching 192.0.2.1...192.0.2.2"
        self.assertIsNone(parser.feed(line))
        recognized = "08[ENC] generating IKE_SA_INIT request 0 [ SA KE No ]"
        self.assertIsNotNone(parser.feed(recognized))
        self.assertIsNone(parser.feed(recognized))


class EspObservationTest(unittest.TestCase):
    def test_summary_validates_peers_and_reports_direction_deltas(self) -> None:
        summary = summarize_esp(FIXTURES / "ike-esp.pcap", EspTotals.empty())
        self.assertIsNotNone(summary)
        assert summary is not None
        self.assertEqual(summary.peer_pair, ("192.0.2.1", "192.0.2.2"))
        self.assertEqual(summary.packet_count, 10)
        self.assertEqual(summary.bytes, 1540)
        self.assertEqual(summary.packet_delta, 10)
        self.assertEqual(summary.byte_delta, 1540)
        self.assertEqual(summary.direction_counts, {"forward": 5, "reverse": 5})
        self.assertEqual(summary.direction_bytes, {"forward": 770, "reverse": 770})

    def test_no_new_esp_packets_suppresses_an_activity_event(self) -> None:
        prior = EspTotals(packet_count=10, bytes=1540)
        self.assertIsNone(summarize_esp(FIXTURES / "ike-esp.pcap", prior))

    def test_unexpected_peer_pair_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "expected transit peers"):
            summarize_esp(
                FIXTURES / "ike-esp.pcap",
                EspTotals.empty(),
                expected_peers=("198.51.100.1", "198.51.100.2"),
            )

    def test_truncated_in_progress_snapshot_is_tolerated(self) -> None:
        with TemporaryDirectory() as directory:
            truncated = Path(directory) / "snapshot.pcap"
            source = (FIXTURES / "ike-esp.pcap").read_bytes()
            truncated.write_bytes(source[:-9])
            self.assertIsNone(summarize_esp(truncated, EspTotals.empty()))


if __name__ == "__main__":
    unittest.main()
