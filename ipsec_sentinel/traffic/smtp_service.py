from __future__ import annotations

import argparse
from email import policy
from email.parser import BytesParser
import hashlib
import json
from pathlib import Path
import signal
import socketserver
import threading

from ipsec_sentinel.artifacts import write_text_atomic


def parse_envelope_path(argument: str, prefix: str) -> str:
    if not argument.upper().startswith(prefix.upper()):
        raise ValueError(f"SMTP envelope argument must start with {prefix}")
    value = argument[len(prefix) :].strip()
    if value.startswith("<"):
        end = value.find(">", 1)
        if end < 0:
            raise ValueError("unterminated SMTP envelope path")
        return value[1:end]
    return value.split(None, 1)[0]


class SmtpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = False
    daemon_threads = True
    receipt_path: Path
    receipt_lock: threading.Lock
    transaction_index: int

    def persist(self, wire: bytes, sender: str, recipients: list[str]) -> None:
        parsed = BytesParser(policy=policy.default).parsebytes(wire)
        body_part = parsed.get_body(preferencelist=("plain",))
        if body_part is None:
            raise ValueError("MIME message lacks a text body")
        body = body_part.get_payload(decode=True) or b""
        attachments = list(parsed.iter_attachments())
        if len(attachments) > 1:
            raise ValueError("only one controlled attachment is supported")
        attachment = b"" if not attachments else attachments[0].get_payload(decode=True) or b""
        with self.receipt_lock:
            self.transaction_index += 1
            receipt = {
                "transaction_index": self.transaction_index,
                "message_id": str(parsed["Message-ID"]),
                "sender": sender,
                "recipients": recipients,
                "body_bytes": len(body),
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "attachment_filename": None if not attachments else attachments[0].get_filename(),
                "attachment_bytes": len(attachment),
                "attachment_sha256": None if not attachments else hashlib.sha256(attachment).hexdigest(),
            }
            with self.receipt_path.open("a", encoding="utf-8") as output:
                output.write(json.dumps(receipt, sort_keys=True) + "\n")
                output.flush()


class SmtpHandler(socketserver.StreamRequestHandler):
    def _reply(self, line: str) -> None:
        self.wfile.write(line.encode("ascii") + b"\r\n")
        self.wfile.flush()

    def handle(self) -> None:
        sender: str | None = None
        recipients: list[str] = []
        self._reply("220 smtp.sentinel.local ESMTP ready")
        while True:
            raw = self.rfile.readline(65_537)
            if not raw or len(raw) > 65_536:
                return
            command = raw.decode("ascii", errors="replace").rstrip("\r\n")
            verb, _, argument = command.partition(" ")
            verb = verb.upper()
            if verb in {"EHLO", "HELO"}:
                self._reply("250-smtp.sentinel.local")
                self._reply("250 SIZE 10485760")
            elif verb == "MAIL" and argument.upper().startswith("FROM:"):
                sender = parse_envelope_path(argument, "FROM:")
                recipients = []
                self._reply("250 sender accepted")
            elif verb == "RCPT" and argument.upper().startswith("TO:") and sender:
                recipients.append(parse_envelope_path(argument, "TO:"))
                self._reply("250 recipient accepted")
            elif verb == "DATA" and sender and recipients:
                self._reply("354 end data with <CR><LF>.<CR><LF>")
                lines: list[bytes] = []
                while True:
                    line = self.rfile.readline(10_485_761)
                    if not line or len(line) > 10_485_760:
                        return
                    if line in {b".\r\n", b".\n"}:
                        break
                    if line.startswith(b".."):
                        line = line[1:]
                    lines.append(line)
                server = self.server
                assert isinstance(server, SmtpServer)
                server.persist(b"".join(lines), sender, recipients)
                self._reply("250 message accepted")
                sender = None
                recipients = []
            elif verb == "RSET":
                sender = None
                recipients = []
                self._reply("250 reset")
            elif verb == "NOOP":
                self._reply("250 ok")
            elif verb == "QUIT":
                self._reply("221 bye")
                return
            else:
                self._reply("503 bad sequence or unsupported command")


def serve(config_path: Path, receipt_path: Path, ready_path: Path) -> None:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    if set(config) != {"bind_address", "port"}:
        raise ValueError("malformed SMTP service plan")
    receipt_path.write_text("", encoding="utf-8")
    server = SmtpServer(
        (str(config["bind_address"]), int(config["port"])), SmtpHandler
    )
    server.receipt_path = receipt_path
    server.receipt_lock = threading.Lock()
    server.transaction_index = 0

    def stop(signum: int, frame: object) -> None:
        del signum, frame
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    write_text_atomic(ready_path, "ready\n")
    try:
        server.serve_forever(poll_interval=0.1)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--receipts", type=Path, required=True)
    parser.add_argument("--ready", type=Path, required=True)
    args = parser.parse_args(argv)
    serve(args.config, args.receipts, args.ready)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
