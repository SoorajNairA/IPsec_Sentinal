from __future__ import annotations

import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import signal
import time
from typing import Any

from ipsec_sentinel.artifacts import write_text_atomic
from ipsec_sentinel.traffic.base import TrafficContext
from ipsec_sentinel.traffic.process import NamespaceServiceProcess


def deterministic_body(seed: int, path: str, size: int) -> bytes:
    if size < 0:
        raise ValueError("resource size must be nonnegative")
    block = hashlib.sha256(f"{seed}:{path}".encode("utf-8")).digest()
    return (block * ((size + len(block) - 1) // len(block)))[:size]


class ResourceServer(ThreadingHTTPServer):
    seed: int
    resources: dict[str, dict[str, object]]
    receipt_path: Path


class ResourceHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        server = self.server
        assert isinstance(server, ResourceServer)
        resource = server.resources.get(self.path)
        if resource is None:
            self.send_error(404)
            return
        body = deterministic_body(server.seed, self.path, int(resource["size"]))
        self.send_response(200)
        self.send_header("Content-Type", str(resource["content_type"]))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        receipt = {
            "path": self.path,
            "status": 200,
            "bytes": len(body),
            "received_unix_ns": time.time_ns(),
        }
        with server.receipt_path.open("a", encoding="utf-8") as output:
            output.write(json.dumps(receipt, sort_keys=True) + "\n")
            output.flush()

    def log_message(self, format: str, *args: object) -> None:
        return None


def _load_service_plan(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    required = {"bind_address", "port", "seed", "resources"}
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("malformed HTTP service plan")
    resources = value["resources"]
    if not isinstance(resources, list) or not resources:
        raise ValueError("HTTP service resources must be nonempty")
    return value


def serve(config_path: Path, receipt_path: Path, ready_path: Path) -> None:
    plan = _load_service_plan(config_path)
    resources = {
        str(item["path"]): {
            "size": int(item["size"]),
            "content_type": str(item["content_type"]),
        }
        for item in plan["resources"]
    }
    receipt_path.write_text("", encoding="utf-8")
    server = ResourceServer(
        (str(plan["bind_address"]), int(plan["port"])), ResourceHandler
    )
    server.seed = int(plan["seed"])
    server.resources = resources
    server.receipt_path = receipt_path

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


class HttpServiceProcess(NamespaceServiceProcess):
    def __init__(
        self, context: TrafficContext, config_path: Path, receipt_path: Path, ready_path: Path
    ) -> None:
        super().__init__(
            context,
            module="ipsec_sentinel.traffic.http_service",
            arguments=(
            "--config",
            str(config_path),
            "--receipts",
            str(receipt_path),
            "--ready",
            str(ready_path),
            ),
            ready_path=ready_path,
            log_name=f"{config_path.stem}.log",
        )
        self.config_path = config_path
        self.receipt_path = receipt_path


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
