from __future__ import annotations

from dataclasses import asdict, dataclass
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
import hashlib
import json
from pathlib import Path
from random import Random
import sys

from ipsec_sentinel.artifacts import write_json_atomic
from ipsec_sentinel.command import run_checked
from ipsec_sentinel.traffic.base import (
    TrafficContext,
    TrafficRunResult,
    TrafficValidation,
)
from ipsec_sentinel.traffic.payload import deterministic_bytes
from ipsec_sentinel.traffic.ports import (
    PortSelection,
    choose_available_port,
    select_port_candidates,
)
from ipsec_sentinel.traffic.process import NamespaceServiceProcess


@dataclass(frozen=True)
class EmailMessagePlan:
    message_id: str
    sender: str
    recipients: tuple[str, ...]
    subject: str
    body_bytes: int
    attachment_filename: str | None
    attachment_bytes: int
    attachment_sha256: str | None
    think_seconds: float
    connection_group: int


@dataclass(frozen=True)
class EmailPlan:
    preferred_port: int
    messages: tuple[EmailMessagePlan, ...]


def _body_text(seed: int, message_id: str, size: int) -> str:
    raw = deterministic_bytes(seed, f"email:body:{message_id}", size)
    return "".join(chr(ord("a") + byte % 26) for byte in raw)


def _attachment(seed: int, message: EmailMessagePlan) -> bytes:
    return deterministic_bytes(
        seed, f"email:attachment:{message.message_id}", message.attachment_bytes
    )


def build_mime_message(message: EmailMessagePlan, seed: int) -> bytes:
    mime = EmailMessage(policy=policy.SMTP)
    mime["From"] = message.sender
    mime["To"] = ", ".join(message.recipients)
    mime["Subject"] = message.subject
    mime["Message-ID"] = message.message_id
    mime.set_content(_body_text(seed, message.message_id, message.body_bytes))
    if message.attachment_bytes:
        payload = _attachment(seed, message)
        if hashlib.sha256(payload).hexdigest() != message.attachment_sha256:
            raise RuntimeError("planned attachment digest mismatch")
        mime.add_attachment(
            payload,
            maintype="application",
            subtype="octet-stream",
            filename=message.attachment_filename,
        )
    return mime.as_bytes(policy=policy.SMTP)


def _receipt_from_wire(
    message: EmailMessagePlan, seed: int, transaction_index: int
) -> dict[str, object]:
    parsed = BytesParser(policy=policy.default).parsebytes(
        build_mime_message(message, seed)
    )
    body_part = parsed.get_body(preferencelist=("plain",))
    if body_part is None:
        raise RuntimeError("planned message has no text body")
    body = body_part.get_payload(decode=True) or b""
    attachments = list(parsed.iter_attachments())
    attachment = b"" if not attachments else attachments[0].get_payload(decode=True) or b""
    return {
        "transaction_index": transaction_index,
        "message_id": message.message_id,
        "sender": message.sender,
        "recipients": list(message.recipients),
        "body_bytes": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "attachment_filename": None if not attachments else attachments[0].get_filename(),
        "attachment_bytes": len(attachment),
        "attachment_sha256": None if not attachments else hashlib.sha256(attachment).hexdigest(),
    }


def expected_email_receipts(plan: EmailPlan, seed: int) -> list[dict[str, object]]:
    return [
        _receipt_from_wire(message, seed, index)
        for index, message in enumerate(plan.messages, start=1)
    ]


def resolve_email_plan(seed: int) -> EmailPlan:
    random = Random(seed)
    count = random.randint(3, 5)
    profiles = ["small", "large", "attachment"]
    profiles.extend(random.choice(("small", "large", "attachment")) for _ in range(count - 3))
    random.shuffle(profiles)
    group = 0
    messages: list[EmailMessagePlan] = []
    for index, profile in enumerate(profiles, start=1):
        if index > 1 and random.choice((True, False)):
            group += 1
        body_size = (
            random.choice((192, 256, 384))
            if profile == "small"
            else random.choice((2048, 4096, 8192))
        )
        attachment_size = (
            random.choice((8192, 16384, 32768, 65536))
            if profile == "attachment"
            else 0
        )
        message_id = f"<ips-{seed}-{index}@sentinel.local>"
        attachment_filename = None if not attachment_size else f"sample-{index}.bin"
        attachment_digest = None
        if attachment_size:
            attachment_digest = hashlib.sha256(
                deterministic_bytes(
                    seed, f"email:attachment:{message_id}", attachment_size
                )
            ).hexdigest()
        recipient_count = random.randint(1, 2)
        recipients = tuple(
            f"recipient-{value}@sentinel.local"
            for value in random.sample(range(1, 5), recipient_count)
        )
        messages.append(
            EmailMessagePlan(
                message_id=message_id,
                sender=f"sender-{random.randint(1, 3)}@sentinel.local",
                recipients=recipients,
                subject=f"Controlled message {seed}-{index}",
                body_bytes=body_size,
                attachment_filename=attachment_filename,
                attachment_bytes=attachment_size,
                attachment_sha256=attachment_digest,
                think_seconds=random.choice((0.02, 0.05, 0.1, 0.15)),
                connection_group=group,
            )
        )
    return EmailPlan(
        select_port_candidates(seed, "email", "tcp")[0], tuple(messages)
    )


def validate_email_result(
    plan: EmailPlan,
    client_records: list[dict[str, object]],
    server_receipts: list[dict[str, object]],
    *,
    seed: int,
) -> TrafficValidation:
    expected_client = [
        {"message_id": message.message_id, "status": "accepted"}
        for message in plan.messages
    ]
    expected_receipts = expected_email_receipts(plan, seed)
    errors: list[str] = []
    if client_records != expected_client:
        errors.append("SMTP client completion ledger does not match the plan")
    if server_receipts != expected_receipts:
        errors.append("SMTP server receipt ledger does not match MIME plan")
    return TrafficValidation(
        not errors,
        {
            "planned_transactions": len(plan.messages),
            "client_completions": len(client_records),
            "server_receipts": len(server_receipts),
            "attachment_bytes": sum(item.attachment_bytes for item in plan.messages),
        },
        tuple(errors),
    )


class EmailGenerator:
    name = "email"
    version = "1"

    def __init__(self, seed: int) -> None:
        self.seed = seed
        self.plan = resolve_email_plan(seed)
        self.port_selection: PortSelection | None = None
        self.service: NamespaceServiceProcess | None = None
        self.client_records: list[dict[str, object]] = []
        self.server_receipts: list[dict[str, object]] = []
        self._result: TrafficRunResult | None = None

    def _paths(self, context: TrafficContext) -> tuple[Path, Path, Path, Path, Path]:
        return (
            context.run_dir / "smtp-service.json",
            context.run_dir / "smtp-receipts.jsonl",
            context.run_dir / "smtp-ready",
            context.run_dir / "smtp-client.json",
            context.run_dir / "smtp-results.json",
        )

    def prepare(self, context: TrafficContext) -> None:
        self.port_selection = choose_available_port(
            context, self.seed, "email", "tcp"
        )
        service_path, receipts, ready, _, _ = self._paths(context)
        write_json_atomic(
            service_path,
            {"bind_address": context.server_ip, "port": self.port_selection.port},
        )
        self.service = NamespaceServiceProcess(
            context,
            module="ipsec_sentinel.traffic.smtp_service",
            arguments=(
                "--config", str(service_path), "--receipts", str(receipts),
                "--ready", str(ready),
            ),
            ready_path=ready,
            log_name="smtp-service.log",
        )
        self.service.start()

    def run(self, context: TrafficContext) -> TrafficRunResult:
        if self.port_selection is None:
            raise RuntimeError("Email generator is not prepared")
        _, receipts, _, client_path, results_path = self._paths(context)
        write_json_atomic(
            client_path,
            {
                "server_ip": context.server_ip,
                "port": self.port_selection.port,
                "seed": self.seed,
                "messages": [asdict(message) for message in self.plan.messages],
            },
        )
        command = run_checked(
            [
                "ip", "netns", "exec", context.client_namespace, sys.executable,
                "-m", "ipsec_sentinel.traffic.smtp_client", "--plan",
                str(client_path), "--output", str(results_path),
            ],
            timeout=30,
            log=context.log,
        )
        payload = json.loads(results_path.read_text(encoding="utf-8"))
        self.client_records = list(payload["records"])
        self.server_receipts = [
            json.loads(line)
            for line in receipts.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self._result = TrafficRunResult(
            {
                "client_records": self.client_records,
                "server_receipts": self.server_receipts,
                "duration_seconds": command.duration_seconds,
            }
        )
        return self._result

    def validate(
        self, context: TrafficContext, result: TrafficRunResult
    ) -> TrafficValidation:
        del context, result
        return validate_email_result(
            self.plan, self.client_records, self.server_receipts, seed=self.seed
        )

    def cleanup(self, context: TrafficContext) -> None:
        del context
        if self.service is not None:
            self.service.stop()
            self.service = None

    def metadata(self) -> dict[str, object]:
        selection = self.port_selection
        return {
            "class": self.name,
            "known_training_class": True,
            "generator": "local-smtp-mime",
            "generator_version": self.version,
            "seed": self.seed,
            "parameters": {
                "preferred_port": self.plan.preferred_port,
                "selected_port": None if selection is None else selection.port,
                "candidate_index": None if selection is None else selection.candidate_index,
                "rejected_ports": [] if selection is None else list(selection.rejected_ports),
                "messages": [asdict(message) for message in self.plan.messages],
            },
            "result": {} if self._result is None else dict(self._result.metrics),
        }
