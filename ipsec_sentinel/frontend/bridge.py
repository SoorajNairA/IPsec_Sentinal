from __future__ import annotations

from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import mimetypes
from pathlib import Path, PurePosixPath
import re
from tempfile import TemporaryDirectory
from typing import Any
from urllib.parse import unquote, urlsplit

from ipsec_sentinel.analyzer.pipeline import analyze_capture
from ipsec_sentinel.frontend.xray import XRAY_SCHEMA_ID, XRAY_VERSION, build_xray_projection


@dataclass(frozen=True)
class FrontendServerConfig:
    static_dir: Path
    model_dir: Path
    host: str = "127.0.0.1"
    port: int = 8_787
    max_upload_bytes: int = 268_435_456
    max_xray_points: int = 1_500

    def __post_init__(self) -> None:
        if self.host != "127.0.0.1":
            raise ValueError("frontend bridge must bind to 127.0.0.1")
        if not 0 <= self.port <= 65_535:
            raise ValueError("invalid bridge port")
        if self.max_upload_bytes <= 0:
            raise ValueError("max_upload_bytes must be positive")


def _empty_xray() -> dict[str, object]:
    return {
        "schema_id": XRAY_SCHEMA_ID,
        "version": XRAY_VERSION,
        "total_packet_count": 0,
        "displayed_packet_count": 0,
        "sampled": False,
        "duration_seconds": 0.0,
        "peer_pair": None,
        "packets": [],
    }


def analyze_for_frontend(
    path: Path,
    *,
    model_dir: Path,
    evidence_dir: Path | None = None,
    max_points: int = 1_500,
) -> dict[str, object]:
    analysis = analyze_capture(
        Path(path),
        model_dir=Path(model_dir),
        evidence_dir=evidence_dir,
    )
    xray = (
        build_xray_projection(Path(path), max_points=max_points)
        if analysis["summary"]["status"] == "COMPLETE"
        else _empty_xray()
    )
    return {"analysis": analysis, "xray": xray}


def sanitize_capture_filename(value: str) -> str:
    name = PurePosixPath(value.replace("\\", "/")).name
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", name).strip("._")
    return safe[:120] or "capture.pcap"


def _analysis_error(analysis: dict[str, Any]) -> tuple[HTTPStatus, str, str]:
    message = str(analysis.get("summary", {}).get("message", "Capture analysis failed."))
    lowered = message.lower()
    if "pcapng" in lowered:
        return HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "UNSUPPORTED_PCAPNG", message
    if "link" in lowered or "ethernet" in lowered:
        return HTTPStatus.UNPROCESSABLE_ENTITY, "UNSUPPORTED_LAYOUT", message
    return HTTPStatus.UNPROCESSABLE_ENTITY, "INVALID_CAPTURE", message


def _handler(config: FrontendServerConfig) -> type[BaseHTTPRequestHandler]:
    static_root = config.static_dir.resolve()

    class FrontendHandler(BaseHTTPRequestHandler):
        server_version = "IPsecSentinel/1.0"

        def log_message(self, _format: str, *_args: object) -> None:
            return

        def _json(self, status: HTTPStatus | int, payload: object) -> None:
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            self.send_response(int(status))
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _error(self, status: HTTPStatus, code: str, message: str) -> None:
            self._json(status, {"error": {"code": code, "message": message}})

        def do_GET(self) -> None:  # noqa: N802
            path = unquote(urlsplit(self.path).path)
            if path == "/api/health":
                self._json(HTTPStatus.OK, {"status": "ok", "analysis_schema": "ipsec-sentinel.analysis/v1"})
                return
            if path.startswith("/api/"):
                self._error(HTTPStatus.NOT_FOUND, "NOT_FOUND", "Unknown API route.")
                return

            relative = path.lstrip("/") or "index.html"
            candidate = (static_root / relative).resolve()
            try:
                candidate.relative_to(static_root)
            except ValueError:
                self._error(HTTPStatus.NOT_FOUND, "NOT_FOUND", "Static asset not found.")
                return
            if not candidate.is_file():
                candidate = static_root / "index.html"
            if not candidate.is_file():
                self._error(HTTPStatus.SERVICE_UNAVAILABLE, "FRONTEND_UNAVAILABLE", "Frontend build is unavailable.")
                return

            body = candidate.read_bytes()
            content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802
            if urlsplit(self.path).path != "/api/analyze":
                self._error(HTTPStatus.NOT_FOUND, "NOT_FOUND", "Unknown API route.")
                return
            try:
                content_length = int(self.headers.get("Content-Length", "-1"))
            except ValueError:
                content_length = -1
            if content_length < 0:
                self._error(HTTPStatus.LENGTH_REQUIRED, "LENGTH_REQUIRED", "Content-Length is required.")
                return
            if content_length > config.max_upload_bytes:
                self._error(HTTPStatus.CONTENT_TOO_LARGE, "PAYLOAD_TOO_LARGE", "Capture exceeds the local upload limit.")
                return
            if self.headers.get_content_type() != "application/octet-stream":
                self._error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "UNSUPPORTED_MEDIA_TYPE", "Upload a raw PCAP body.")
                return

            filename = sanitize_capture_filename(self.headers.get("X-Capture-Filename", "capture.pcap"))
            try:
                with TemporaryDirectory(prefix="ipsec-sentinel-upload-") as directory:
                    path = Path(directory) / filename
                    remaining = content_length
                    with path.open("wb") as output:
                        while remaining:
                            chunk = self.rfile.read(min(1_048_576, remaining))
                            if not chunk:
                                raise ValueError("Upload ended before Content-Length bytes were received.")
                            output.write(chunk)
                            remaining -= len(chunk)
                    envelope = analyze_for_frontend(
                        path,
                        model_dir=config.model_dir,
                        max_points=config.max_xray_points,
                    )
                    analysis = envelope["analysis"]
                    if analysis["summary"]["status"] != "COMPLETE":
                        status, code, message = _analysis_error(analysis)
                        self._json(status, {"error": {"code": code, "message": message}, "analysis": analysis})
                        return
                    self._json(HTTPStatus.OK, envelope)
            except ValueError as error:
                self._error(HTTPStatus.BAD_REQUEST, "INVALID_UPLOAD", str(error))
            except Exception:
                self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "ANALYZER_FAILURE", "Local analysis could not be completed.")

    return FrontendHandler


def create_server(config: FrontendServerConfig) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((config.host, config.port), _handler(config))


def serve(config: FrontendServerConfig) -> None:
    server = create_server(config)
    try:
        server.serve_forever()
    finally:
        server.server_close()

