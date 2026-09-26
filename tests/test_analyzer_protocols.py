from pathlib import Path
from tempfile import TemporaryDirectory
import struct
import unittest

from ipsec_sentinel.analyzer.capture import parse_capture
from ipsec_sentinel.analyzer.ike import analyze_ike, normalize_transform
from ipsec_sentinel.analyzer.protocols import analyze_protocols
from ipsec_sentinel.analyzer.sa import reconstruct_security_associations
from tests.pcap_helpers import ethernet_ipv4, write_pcap


def udp(source: int, destination: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", source, destination, 8 + len(payload), 0) + payload


def transform(last: int, kind: int, transform_id: int, key_bits: int | None = None) -> bytes:
    attributes = b"" if key_bits is None else struct.pack("!HH", 0x800E, key_bits)
    return struct.pack("!BBHBBH", last, 0, 8 + len(attributes), kind, 0, transform_id) + attributes


def ike_sa_response() -> bytes:
    transforms = b"".join((
        transform(3, 1, 20, 256),
        transform(3, 2, 5),
        transform(3, 3, 12),
        transform(0, 4, 20),
    ))
    proposal = struct.pack("!BBHBBBB", 0, 0, 8 + len(transforms), 1, 1, 0, 4) + transforms
    sa = struct.pack("!BBH", 0, 0, 4 + len(proposal)) + proposal
    header = struct.pack(
        "!8s8sBBBBII", b"INITSPI1", b"RESPSPI1", 33, 0x20, 34, 0x20, 0, 28 + len(sa)
    )
    return header + sa


def esp(spi: int, sequence: int, payload: bytes = b"x" * 16) -> bytes:
    return struct.pack("!II", spi, sequence) + payload


class AnalyzerProtocolTest(unittest.TestCase):
    def _capture(self, records: list[tuple[int, bytes]]):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "capture.pcap"
        write_pcap(path, records)
        return parse_capture(path)

    def test_detects_ikev2_esp_ah_natt_and_peers(self) -> None:
        capture = self._capture([
            (1, ethernet_ipv4("192.0.2.1", "192.0.2.2", 17, udp(500, 500, ike_sa_response()))),
            (2, ethernet_ipv4("192.0.2.2", "192.0.2.1", 50, esp(0x11111111, 1))),
            (3, ethernet_ipv4("192.0.2.1", "192.0.2.2", 51, b"\x00" * 16)),
            (4, ethernet_ipv4("192.0.2.2", "192.0.2.1", 17, udp(4500, 4500, b"\0\0\0\0" + ike_sa_response()))),
        ])
        protocols, evidence = analyze_protocols(capture)
        self.assertTrue(protocols["ipsec_detected"])
        self.assertEqual(protocols["ike_packets"], 2)
        self.assertEqual(protocols["esp_packets"], 1)
        self.assertEqual(protocols["ah_packets"], 1)
        self.assertEqual(protocols["natt_packets"], 1)
        self.assertEqual(protocols["ike_version"], "IKEv2")
        self.assertEqual(protocols["peer_pairs"], [["192.0.2.1", "192.0.2.2"]])
        self.assertTrue(all(item.provenance == "OBSERVED" for item in evidence))

    def test_selected_ike_algorithms_come_from_responder_selection(self) -> None:
        capture = self._capture([
            (1, ethernet_ipv4("192.0.2.2", "192.0.2.1", 17, udp(500, 500, ike_sa_response())))
        ])
        result, evidence = analyze_ike(capture)
        self.assertEqual(result["version"], "IKEv2")
        self.assertEqual(result["encryption"]["normalized"], "AES-256-GCM")
        self.assertEqual(result["integrity"]["normalized"], "HMAC-SHA-256")
        self.assertEqual(result["prf"]["normalized"], "PRF-HMAC-SHA-256")
        self.assertEqual(result["dh_group"]["normalized"], "ECP-384")
        self.assertEqual(result["selection_basis"], "IKE_SA_INIT responder SA payload")
        self.assertEqual({item.provenance for item in evidence}, {"OBSERVED"})

    def test_algorithm_normalization(self) -> None:
        self.assertEqual(normalize_transform(1, 20, 128), ("AES_GCM_16_128", "AES-128-GCM"))
        self.assertEqual(normalize_transform(1, 12, 256), ("AES_CBC_256", "AES-256-CBC"))
        self.assertEqual(normalize_transform(3, 12, None), ("AUTH_HMAC_SHA2_256_128", "HMAC-SHA-256"))
        self.assertEqual(normalize_transform(4, 20, None), ("ECP_384", "ECP-384"))

    def test_spi_replacement_is_rekey_derived_but_pfs_unknown(self) -> None:
        capture = self._capture([
            (1, ethernet_ipv4("192.0.2.1", "192.0.2.2", 50, esp(1, 1))),
            (2, ethernet_ipv4("192.0.2.1", "192.0.2.2", 50, esp(1, 1))),  # retransmission
            (3, ethernet_ipv4("192.0.2.2", "192.0.2.1", 50, esp(2, 1))),
            (4, ethernet_ipv4("192.0.2.1", "192.0.2.2", 50, esp(3, 1))),
            (5, ethernet_ipv4("192.0.2.2", "192.0.2.1", 50, esp(4, 1))),
        ])
        associations, evidence = reconstruct_security_associations(capture)
        self.assertEqual([sa["spi"] for sa in associations], ["0x00000001", "0x00000002", "0x00000003", "0x00000004"])
        self.assertEqual(associations[0]["unique_packet_count"], 1)
        self.assertEqual(associations[0]["successor_spi"], "0x00000003")
        self.assertEqual(associations[2]["predecessor_spi"], "0x00000001")
        self.assertEqual(associations[2]["rekey_provenance"], "DERIVED")
        self.assertEqual(associations[2]["pfs"], {"state": "unknown", "provenance": "UNKNOWN"})
        self.assertTrue(any(item.provenance == "DERIVED" for item in evidence))


if __name__ == "__main__":
    unittest.main()
