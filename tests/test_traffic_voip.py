import hashlib
import unittest

from ipsec_sentinel.traffic.payload import deterministic_bytes
from ipsec_sentinel.traffic.rtp_peer import build_rtp_packet, parse_rtp_packet
from ipsec_sentinel.traffic.voip import resolve_voip_plan, validate_voip_result


def records(direction, source: str, destination: str, seed: int = 401):
    return [
        {
            "sequence": event.sequence,
            "timestamp": event.timestamp,
            "ssrc": direction.ssrc,
            "payload_type": direction.payload_type,
            "payload_bytes": event.payload_bytes,
            "payload_sha256": hashlib.sha256(
                deterministic_bytes(
                    seed,
                    f"voip:{direction.name}:{event.sequence}",
                    event.payload_bytes,
                )
            ).hexdigest(),
            "source_ip": source,
            "destination_ip": destination,
        }
        for event in direction.events
    ]


class VoipGeneratorTest(unittest.TestCase):
    def test_same_seed_reproduces_plan_and_seed_set_varies_voice_behavior(self) -> None:
        first = resolve_voip_plan(401)
        self.assertEqual(first, resolve_voip_plan(401))
        plans = [resolve_voip_plan(seed) for seed in range(401, 413)]
        self.assertGreater(len({plan.packetization_interval_ms for plan in plans}), 1)
        self.assertGreater(len({plan.duration_seconds for plan in plans}), 1)
        self.assertGreater(
            len({tuple(event.payload_bytes for event in plan.client_to_server.events) for plan in plans}),
            1,
        )
        self.assertGreater(
            len({(len(plan.client_to_server.events), len(plan.server_to_client.events)) for plan in plans}),
            1,
        )
        self.assertTrue(3.5 <= first.duration_seconds <= 7.0)
        self.assertIn(first.packetization_interval_ms, (10, 20, 30))

    def test_rtp_codec_uses_version_two_and_preserves_header_fields(self) -> None:
        packet = build_rtp_packet(
            payload_type=111,
            sequence=65530,
            timestamp=0xDEADBEEF,
            ssrc=0x12345678,
            payload=b"voice-payload",
        )
        parsed = parse_rtp_packet(packet)
        self.assertEqual(parsed["version"], 2)
        self.assertEqual(parsed["payload_type"], 111)
        self.assertEqual(parsed["sequence"], 65530)
        self.assertEqual(parsed["timestamp"], 0xDEADBEEF)
        self.assertEqual(parsed["ssrc"], 0x12345678)
        self.assertEqual(parsed["payload"], b"voice-payload")

    def test_validation_requires_exact_bidirectional_delivery_and_timing(self) -> None:
        plan = resolve_voip_plan(401)
        client_sent = records(plan.client_to_server, "10.10.0.2", "10.20.0.2")
        server_sent = records(plan.server_to_client, "10.20.0.2", "10.10.0.2")
        client = {"sent": client_sent, "received": server_sent}
        server = {"sent": server_sent, "received": client_sent}
        validation = validate_voip_result(
            plan, client, server, realized_duration_seconds=plan.duration_seconds
        )
        self.assertTrue(validation.passed, validation.errors)

        missing = {"sent": client_sent, "received": server_sent[:-1]}
        failed = validate_voip_result(
            plan, missing, server, realized_duration_seconds=plan.duration_seconds
        )
        self.assertFalse(failed.passed)
        self.assertTrue(any("bidirectional" in error for error in failed.errors))


if __name__ == "__main__":
    unittest.main()
