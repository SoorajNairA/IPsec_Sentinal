from __future__ import annotations

import argparse
from hmac import compare_digest
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import signal
import ssl
import subprocess
import sys
from threading import Lock, Thread
from typing import Any

from ipsec_sentinel.artifacts import write_json_atomic


API_VERSION = "ipsec-sentinel.cloud-endpoint/v1"
MAX_BODY = 64 * 1024
RUNTIME_ROOT = Path("/run/ipsec-sentinel-endpoint")


class EndpointState:
    def __init__(self, token: str, runtime_root: Path = RUNTIME_ROOT) -> None:
        self.token = token
        self.runtime_root = runtime_root
        self.runtime_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.runtime_root, 0o700)
        self.lock = Lock()
        self.nonce: str | None = None
        self.video: subprocess.Popen[str] | None = None
        self.output: Any | None = None

    def authenticate(self, authorization: str, nonce: str) -> bool:
        expected = f"Bearer {self.token}"
        return (
            len(authorization) == len(expected)
            and compare_digest(authorization, expected)
            and bool(nonce)
            and len(nonce) <= 128
        )

    def prepare_video(self, nonce: str, payload: dict[str, Any]) -> dict[str, object]:
        required = {"seed", "port", "resources"}
        if set(payload) != required:
            raise ValueError("video plan keys do not match the endpoint schema")
        port = int(payload["port"])
        if not 20_000 <= port <= 49_999:
            raise ValueError("video port is outside the controlled range")
        resources = payload["resources"]
        if not isinstance(resources, list) or not 5 <= len(resources) <= 7:
            raise ValueError("video resources must contain 5..7 segments")
        normalized: list[dict[str, object]] = []
        for resource in resources:
            if not isinstance(resource, dict) or set(resource) != {"path", "size", "content_type"}:
                raise ValueError("video resource is malformed")
            path = str(resource["path"])
            size = int(resource["size"])
            if not path.startswith("/video/segment-") or not path.endswith(".bin"):
                raise ValueError("video resource path is outside the allowlist")
            if not 32_000 <= size <= 400_000:
                raise ValueError("video resource size is outside the controlled range")
            normalized.append({"path": path, "size": size, "content_type": "video/mp2t"})
        with self.lock:
            if self.video is not None and self.video.poll() is None:
                raise RuntimeError("a video workload is already prepared")
            self.cleanup_video()
            plan_path = self.runtime_root / "video-plan.json"
            receipts = self.runtime_root / "video-receipts.jsonl"
            ready = self.runtime_root / "video-ready"
            write_json_atomic(
                plan_path,
                {
                    "bind_address": "10.20.0.2",
                    "port": port,
                    "seed": int(payload["seed"]),
                    "resources": normalized,
                },
            )
            output_path = self.runtime_root / "video-service.log"
            self.output = output_path.open("w", encoding="utf-8")
            self.video = subprocess.Popen(
                [
                    "ip", "netns", "exec", "ips-server", sys.executable,
                    "-m", "ipsec_sentinel.traffic.http_service",
                    "--config", str(plan_path), "--receipts", str(receipts),
                    "--ready", str(ready),
                ],
                stdout=self.output,
                stderr=subprocess.STDOUT,
                text=True,
            )
            self.nonce = nonce
            for _ in range(100):
                if ready.is_file():
                    return {"status": "ready", "port": port, "resource_count": len(normalized)}
                if self.video.poll() is not None:
                    raise RuntimeError("video service exited before readiness")
                __import__("time").sleep(0.05)
            self.cleanup_video()
            raise TimeoutError("video service readiness timed out")

    def video_receipts(self, nonce: str) -> dict[str, object]:
        with self.lock:
            if self.nonce != nonce:
                raise PermissionError("session nonce does not own the video workload")
            path = self.runtime_root / "video-receipts.jsonl"
            receipts = [] if not path.is_file() else [
                json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
            ]
            return {"status": "ready", "receipts": receipts}

    def cleanup_video(self) -> dict[str, object]:
        process, self.video = self.video, None
        try:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        finally:
            if self.output is not None:
                self.output.close()
                self.output = None
            self.nonce = None
            (self.runtime_root / "video-ready").unlink(missing_ok=True)
        return {"status": "stopped"}

    def evidence(self) -> dict[str, object]:
        def command(argv: list[str]) -> str:
            completed = subprocess.run(
                argv, text=True, capture_output=True, check=False, timeout=8
            )
            if completed.returncode != 0:
                raise RuntimeError(f"evidence command failed: {argv[0]}")
            return completed.stdout

        return {
            "schema": API_VERSION,
            "swanctl": command(["swanctl", "--list-sas", "--raw"]),
            "xfrm_state": command(["ip", "xfrm", "state"]),
            "xfrm_policy": command(["ip", "xfrm", "policy"]),
        }


class EndpointServer(ThreadingHTTPServer):
    state: EndpointState


class EndpointHandler(BaseHTTPRequestHandler):
    server_version = "IPsecSentinelEndpoint/1"

    def log_message(self, format: str, *args: object) -> None:
        return None

    def _json(self, status: HTTPStatus, payload: dict[str, object]) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _authorize(self) -> str | None:
        nonce = self.headers.get("X-Sentinel-Session", "")
        if not self.server.state.authenticate(self.headers.get("Authorization", ""), nonce):
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return None
        return nonce

    def _payload(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > MAX_BODY:
            raise ValueError("request body size is invalid")
        value = json.loads(self.rfile.read(length))
        if not isinstance(value, dict):
            raise ValueError("request body must be an object")
        return value

    def do_GET(self) -> None:
        nonce = self._authorize()
        if nonce is None:
            return
        try:
            if self.path == "/v1/health":
                payload = {"schema": API_VERSION, "ready": True}
            elif self.path == "/v1/evidence":
                payload = self.server.state.evidence()
            elif self.path == "/v1/video/receipt":
                payload = self.server.state.video_receipts(nonce)
            else:
                self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            self._json(HTTPStatus.OK, payload)
        except PermissionError:
            self._json(HTTPStatus.CONFLICT, {"error": "session mismatch"})
        except BaseException:
            self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "endpoint operation failed"})

    def do_POST(self) -> None:
        nonce = self._authorize()
        if nonce is None:
            return
        try:
            if self.path == "/v1/video/prepare":
                payload = self.server.state.prepare_video(nonce, self._payload())
            elif self.path == "/v1/video/cleanup":
                if int(self.headers.get("Content-Length", "0")) not in (0, 2):
                    raise ValueError("cleanup body is invalid")
                payload = self.server.state.cleanup_video()
            else:
                self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            self._json(HTTPStatus.OK, payload)
        except (ValueError, json.JSONDecodeError):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid request"})
        except RuntimeError:
            self._json(HTTPStatus.CONFLICT, {"error": "endpoint busy"})
        except BaseException:
            self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "endpoint operation failed"})


def serve(address: str, port: int, token_file: Path, cert: Path, key: Path) -> None:
    token = token_file.read_text(encoding="utf-8").strip()
    if len(token) < 32:
        raise ValueError("control token must contain at least 32 characters")
    server = EndpointServer((address, port), EndpointHandler)
    server.state = EndpointState(token)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)

    def stop(_signum: int, _frame: object) -> None:
        Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.state.cleanup_video()
        server.server_close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--address", default="10.20.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--cert", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    args = parser.parse_args(argv)
    serve(args.address, args.port, args.token_file, args.cert, args.key)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
