from __future__ import annotations

import argparse
import json
from pathlib import Path
import smtplib
import time

from ipsec_sentinel.artifacts import write_json_atomic
from ipsec_sentinel.traffic.email import EmailMessagePlan, build_mime_message


def execute_plan(plan: dict[str, object]) -> list[dict[str, object]]:
    messages = plan["messages"]
    if not isinstance(messages, list):
        raise ValueError("SMTP messages must be a list")
    connection: smtplib.SMTP | None = None
    current_group: int | None = None
    records: list[dict[str, object]] = []
    try:
        for raw in messages:
            if not isinstance(raw, dict):
                raise ValueError("malformed SMTP message plan")
            message = EmailMessagePlan(
                message_id=str(raw["message_id"]),
                sender=str(raw["sender"]),
                recipients=tuple(str(value) for value in raw["recipients"]),
                subject=str(raw["subject"]),
                body_bytes=int(raw["body_bytes"]),
                attachment_filename=(
                    None if raw["attachment_filename"] is None
                    else str(raw["attachment_filename"])
                ),
                attachment_bytes=int(raw["attachment_bytes"]),
                attachment_sha256=(
                    None if raw["attachment_sha256"] is None
                    else str(raw["attachment_sha256"])
                ),
                think_seconds=float(raw["think_seconds"]),
                connection_group=int(raw["connection_group"]),
            )
            if connection is None or current_group != message.connection_group:
                if connection is not None:
                    connection.quit()
                connection = smtplib.SMTP(
                    str(plan["server_ip"]), int(plan["port"]), timeout=5
                )
                connection.ehlo("client.sentinel.local")
                current_group = message.connection_group
            refused = connection.sendmail(
                message.sender,
                list(message.recipients),
                build_mime_message(message, int(plan["seed"])),
            )
            if refused:
                raise RuntimeError(f"SMTP recipients refused: {sorted(refused)}")
            records.append({"message_id": message.message_id, "status": "accepted"})
            time.sleep(message.think_seconds)
    finally:
        if connection is not None:
            try:
                connection.quit()
            except (OSError, smtplib.SMTPException):
                connection.close()
    return records


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    plan = json.loads(args.plan.read_text(encoding="utf-8"))
    started = time.monotonic()
    records = execute_plan(plan)
    write_json_atomic(
        args.output,
        {"records": records, "duration_seconds": time.monotonic() - started},
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
