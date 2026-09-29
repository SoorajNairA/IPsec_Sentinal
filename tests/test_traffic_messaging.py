import unittest

from ipsec_sentinel.traffic.messaging import (
    expected_message_records,
    resolve_messaging_plan,
    validate_messaging_result,
)
from ipsec_sentinel.traffic.messaging_peer import (
    build_message_frame,
    parse_message_frame,
)


class MessagingGeneratorTest(unittest.TestCase):
    def test_same_seed_reproduces_plan_and_seed_set_varies_interaction(self) -> None:
        first = resolve_messaging_plan(601)
        self.assertEqual(first, resolve_messaging_plan(601))
        plans = [resolve_messaging_plan(seed) for seed in range(601, 613)]
        self.assertGreater(len({len(plan.messages) for plan in plans}), 1)
        self.assertGreater(
            len({tuple(item.payload_bytes for item in plan.messages) for plan in plans}),
            1,
        )
        self.assertGreater(
            len({tuple(item.idle_before_seconds for item in plan.messages) for plan in plans}),
            1,
        )
        self.assertGreater(
            len({tuple(item.direction for item in plan.messages) for plan in plans}),
            1,
        )
        self.assertGreater(len({item.burst_index for item in first.messages}), 1)
        self.assertEqual(
            {item.direction for item in first.messages},
            {"client_to_server", "server_to_client"},
        )

    def test_length_framed_message_preserves_identity_size_and_digest(self) -> None:
        plan = resolve_messaging_plan(601)
        message = plan.messages[0]
        frame = build_message_frame(message, 601)
        parsed = parse_message_frame(frame)
        self.assertEqual(parsed["message_id"], message.message_id)
        self.assertEqual(parsed["direction"], message.direction)
        self.assertEqual(parsed["payload_bytes"], message.payload_bytes)
        self.assertEqual(len(parsed["payload_sha256"]), 64)

    def test_validation_requires_both_endpoint_ledgers(self) -> None:
        plan = resolve_messaging_plan(601)
        expected = expected_message_records(plan, 601)
        up = [item for item in expected if item["direction"] == "client_to_server"]
        down = [item for item in expected if item["direction"] == "server_to_client"]
        client = {"sent": up, "received": down, "connection_count": 1}
        server = {"sent": down, "received": up, "connection_count": 1}
        validation = validate_messaging_result(
            plan,
            client,
            server,
            realized_duration_seconds=plan.expected_duration_seconds,
            seed=601,
        )
        self.assertTrue(validation.passed, validation.errors)
        failed = validate_messaging_result(
            plan,
            client,
            {"sent": down, "received": up[:-1], "connection_count": 1},
            realized_duration_seconds=plan.expected_duration_seconds,
            seed=601,
        )
        self.assertFalse(failed.passed)
        self.assertTrue(any("endpoint" in error for error in failed.errors))


if __name__ == "__main__":
    unittest.main()
