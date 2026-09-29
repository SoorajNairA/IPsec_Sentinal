from email import policy
from email.parser import BytesParser
import hashlib
import unittest

from ipsec_sentinel.traffic.email import (
    build_mime_message,
    expected_email_receipts,
    resolve_email_plan,
    validate_email_result,
)
from ipsec_sentinel.traffic.smtp_service import parse_envelope_path


class EmailGeneratorTest(unittest.TestCase):
    def test_esmtp_envelope_parser_excludes_size_and_other_options(self) -> None:
        self.assertEqual(
            parse_envelope_path("FROM:<sender@sentinel.local> size=25193", "FROM:"),
            "sender@sentinel.local",
        )
        self.assertEqual(
            parse_envelope_path("TO:<recipient@sentinel.local>", "TO:"),
            "recipient@sentinel.local",
        )

    def test_same_seed_reproduces_plan_and_seed_set_varies_mail_behavior(self) -> None:
        first = resolve_email_plan(501)
        self.assertEqual(first, resolve_email_plan(501))
        plans = [resolve_email_plan(seed) for seed in range(501, 513)]
        self.assertTrue(3 <= len(first.messages) <= 5)
        self.assertGreater(len({len(plan.messages) for plan in plans}), 1)
        self.assertGreater(
            len({tuple(item.body_bytes for item in plan.messages) for plan in plans}),
            1,
        )
        self.assertGreater(
            len({tuple(item.attachment_bytes for item in plan.messages) for plan in plans}),
            1,
        )
        self.assertGreater(
            len({tuple(item.think_seconds for item in plan.messages) for plan in plans}),
            1,
        )
        self.assertGreater(
            len({tuple(item.connection_group for item in plan.messages) for plan in plans}),
            1,
        )
        self.assertTrue(any(item.attachment_bytes > 0 for item in first.messages))

    def test_mime_message_contains_real_body_and_checksum_verified_attachment(self) -> None:
        plan = resolve_email_plan(501)
        message_plan = next(
            item for item in plan.messages if item.attachment_bytes > 0
        )
        wire = build_mime_message(message_plan, 501)
        parsed = BytesParser(policy=policy.default).parsebytes(wire)
        self.assertEqual(parsed["Message-ID"], message_plan.message_id)
        body = parsed.get_body(preferencelist=("plain",)).get_payload(decode=True)
        self.assertGreaterEqual(len(body), message_plan.body_bytes)
        attachments = list(parsed.iter_attachments())
        self.assertEqual(len(attachments), 1)
        payload = attachments[0].get_payload(decode=True)
        self.assertEqual(len(payload), message_plan.attachment_bytes)
        self.assertEqual(
            hashlib.sha256(payload).hexdigest(),
            message_plan.attachment_sha256,
        )

    def test_validation_requires_server_receipt_ledger_not_client_success_only(self) -> None:
        plan = resolve_email_plan(501)
        receipts = expected_email_receipts(plan, 501)
        client = [
            {"message_id": item.message_id, "status": "accepted"}
            for item in plan.messages
        ]
        self.assertTrue(validate_email_result(plan, client, receipts, seed=501).passed)
        failed = validate_email_result(plan, client, receipts[:-1], seed=501)
        self.assertFalse(failed.passed)
        self.assertTrue(any("receipt" in error for error in failed.errors))


if __name__ == "__main__":
    unittest.main()
