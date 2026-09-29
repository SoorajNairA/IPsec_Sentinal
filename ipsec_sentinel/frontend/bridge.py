from __future__ import annotations

from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import mimetypes
from pathlib import Path, PurePosixPath
import re
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, unquote, urlsplit

from ipsec_sentinel.analyzer.pipeline import analyze_capture
from ipsec_sentinel.frontend.xray import XRAY_SCHEMA_ID, XRAY_VERSION, build_xray_projection
from ipsec_sentinel.live.events import format_heartbeat, format_sse
from ipsec_sentinel.live.models import LiveProblem

if TYPE_CHECKING:
    from ipsec_sentinel.live.api import LiveLabApi
    from ipsec_sentinel.live.orchestrator import LiveLabOrchestrator


@dataclass(frozen=True)
class FrontendServerConfig:
    static_dir: Path
    model_dir: Path
    host: str = "127.0.0.1"
    port: int = 8_787
    max_upload_bytes: int = 268_435_456
    max_xray_points: int = 1_500
    enable_live_lab: bool = False
    live_runs_dir: Path = Path("runs/live")
    lab_provider: str = "local"
    gcp_config: Path | None = None
    sse_heartbeat_seconds: float = 15.0

    def __post_init__(self) -> None:
        if self.host != "127.0.0.1":
            raise ValueError("frontend bridge must bind to 127.0.0.1")
        if not 0 <= self.port <= 65_535:
            raise ValueError("invalid bridge port")
        if self.max_upload_bytes <= 0:
            raise ValueError("max_upload_bytes must be positive")
        if self.sse_heartbeat_seconds <= 0:
            raise ValueError("sse_heartbeat_seconds must be positive")
        if self.lab_provider not in {"local", "gcp"}:
            raise ValueError("lab_provider must be local or gcp")
        if self.lab_provider == "gcp" and self.gcp_config is None:
            raise ValueError("gcp_config is required for the GCP provider")


def _empty_xray(
    *,
    capture_source: str | None = None,
    capture_path: Path | None = None,
) -> dict[str, object]:
    projection: dict[str, object] = {
        "schema_id": XRAY_SCHEMA_ID,
        "version": XRAY_VERSION,
        "total_packet_count": 0,
        "displayed_packet_count": 0,
        "sampled": False,
        "duration_seconds": 0.0,
        "peer_pair": None,
        "packets": [],
    }
    if capture_source is not None:
        projection["capture_source"] = capture_source
        projection["capture_path"] = str(capture_path)
    return projection


def analyze_for_frontend(
    path: Path,
    *,
    model_dir: Path,
    evidence_dir: Path | None = None,
    max_points: int = 1_500,
    traffic_capture_path: Path | None = None,
) -> dict[str, object]:
    analysis = analyze_capture(
        Path(path),
        model_dir=Path(model_dir),
        evidence_dir=evidence_dir,
        traffic_capture_path=traffic_capture_path,
    )
    xray_path = Path(path) if traffic_capture_path is None else Path(traffic_capture_path)
    xray_source = None if traffic_capture_path is None else "WORKLOAD_WINDOW"
    if analysis["summary"]["status"] == "COMPLETE":
        try:
            xray = build_xray_projection(
                xray_path,
                max_points=max_points,
                capture_source=xray_source,
            )
        except (OSError, ValueError):
            xray = _empty_xray(
                capture_source=xray_source,
                capture_path=xray_path,
            )
    else:
        xray = _empty_xray(
            capture_source=xray_source,
            capture_path=xray_path if xray_source is not None else None,
        )
    return {"analysis": analysis, "xray": xray}


def sanitize_capture_filename(value: str) -> str:
    name = PurePosixPath(value.replace("\\", "/")).name
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", name).strip("._")
    return safe[:120] or "capture.pcap"


def _analysis_error(analysis: dict[str, Any]) -> tuple[HTTPStatus, str, str]:
    message = str(analysis.get("summary", {}).get("message", "Capture analysis failed."))
    ipsec_state = str(analysis.get("summary", {}).get("ipsec", "")).upper()
    lowered = message.lower()
    if ipsec_state in {"NOT_DETECTED", "ABSENT"} or ("ipsec" in lowered and "not" in lowered):
        return HTTPStatus.UNPROCESSABLE_ENTITY, "NO_IPSEC", "No IPsec traffic was detected in the capture."
    if "pcapng" in lowered:
        return HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "UNSUPPORTED_PCAPNG", message
    if "link" in lowered or "ethernet" in lowered:
        return HTTPStatus.UNPROCESSABLE_ENTITY, "UNSUPPORTED_LAYOUT", message
    return HTTPStatus.UNPROCESSABLE_ENTITY, "INVALID_CAPTURE", message


def _handler(
    config: FrontendServerConfig,
    live_api: LiveLabApi | None,
) -> type[BaseHTTPRequestHandler]:
    static_root = config.static_dir.resolve()

    class FrontendHandler(BaseHTTPRequestHandler):
        server_version = "IPsecSentinel/1.0"
        protocol_version = "HTTP/1.1"

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

        def _host_is_loopback(self) -> bool:
            host = self.headers.get("Host", "").strip().lower()
            if host.startswith("["):
                hostname = host.split("]", 1)[0] + "]"
            else:
                hostname = host.split(":", 1)[0]
            return hostname in {"127.0.0.1", "localhost", "[::1]"}

        def _require_loopback_host(self) -> bool:
            if self._host_is_loopback():
                return True
            self._error(
                HTTPStatus.FORBIDDEN,
                "LOOPBACK_HOST_REQUIRED",
                "The Sentinel Agent accepts loopback Host values only.",
            )
            return False

        def _live(self) -> LiveLabApi | None:
            if live_api is not None:
                return live_api
            self._error(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "LIVE_LAB_UNAVAILABLE",
                "Live Lab is disabled; start the agent with --enable-live-lab.",
            )
            return None

        def _read_json(self) -> dict[str, object] | None:
            if self.headers.get_content_type() != "application/json":
                self._error(
                    HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                    "JSON_REQUIRED",
                    "Live Lab mutation requests require application/json.",
                )
                return None
            try:
                content_length = int(self.headers.get("Content-Length", "-1"))
            except ValueError:
                content_length = -1
            if content_length < 0:
                self._error(
                    HTTPStatus.LENGTH_REQUIRED,
                    "LENGTH_REQUIRED",
                    "Content-Length is required.",
                )
                return None
            if content_length > 65_536:
                self._error(
                    HTTPStatus.CONTENT_TOO_LARGE,
                    "PAYLOAD_TOO_LARGE",
                    "Live Lab request exceeds the JSON limit.",
                )
                return None
            try:
                payload = json.loads(self.rfile.read(content_length))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._error(
                    HTTPStatus.BAD_REQUEST,
                    "INVALID_JSON",
                    "Request body is not valid JSON.",
                )
                return None
            if not isinstance(payload, dict):
                self._error(
                    HTTPStatus.BAD_REQUEST,
                    "INVALID_REQUEST",
                    "Request body must be a JSON object.",
                )
                return None
            return payload

        def _live_problem(self, problem: LiveProblem) -> None:
            self._json(problem.http_status, problem.to_dict())

        def _stream_events(
            self,
            api: LiveLabApi,
            session_id: str,
            after_id: int,
        ) -> None:
            try:
                api.orchestrator.get_session(session_id)
            except LiveProblem as problem:
                self._live_problem(problem)
                return
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "keep-alive")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
            cursor = after_id
            pending = api.events(session_id, cursor)
            try:
                while True:
                    if not pending:
                        pending = api.wait_events(
                            session_id,
                            cursor,
                            config.sse_heartbeat_seconds,
                        )
                    if pending:
                        for event in pending:
                            self.wfile.write(format_sse(event))
                            cursor = event.event_id
                        pending = ()
                    else:
                        self.wfile.write(format_heartbeat())
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, TimeoutError):
                self.close_connection = True

        def do_GET(self) -> None:  # noqa: N802
            if not self._require_loopback_host():
                return
            parsed = urlsplit(self.path)
            path = unquote(parsed.path)
            if path == "/api/health":
                self._json(HTTPStatus.OK, {
                    "status": "ok",
                    "analysis_schema": "ipsec-sentinel.analysis/v1",
                    "live_lab": live_api is not None,
                })
                return
            if path.startswith("/api/lab/") or path == "/api/lab/scenarios":
                api = self._live()
                if api is None:
                    return
                try:
                    if path == "/api/lab/scenarios":
                        response = api.scenarios()
                        self._json(response.status, response.payload)
                        return
                    match = re.fullmatch(r"/api/lab/sessions/([^/]+)", path)
                    if match:
                        response = api.get_session(match.group(1))
                        self._json(response.status, response.payload)
                        return
                    match = re.fullmatch(
                        r"/api/lab/sessions/([^/]+)/events", path
                    )
                    if match:
                        query = parse_qs(parsed.query, keep_blank_values=True)
                        raw_cursor = self.headers.get("Last-Event-ID")
                        if raw_cursor is None:
                            raw_cursor = next(
                                iter(
                                    query.get("lastEventId", [])
                                    or query.get("last_event_id", [])
                                    or ["0"]
                                )
                            )
                        try:
                            after_id = int(raw_cursor)
                            if after_id < 0:
                                raise ValueError
                        except (TypeError, ValueError):
                            self._error(
                                HTTPStatus.BAD_REQUEST,
                                "INVALID_EVENT_ID",
                                "Last-Event-ID must be a non-negative integer.",
                            )
                            return
                        self._stream_events(api, match.group(1), after_id)
                        return
                except LiveProblem as problem:
                    self._live_problem(problem)
                    return
                self._error(
                    HTTPStatus.NOT_FOUND,
                    "NOT_FOUND",
                    "Unknown Live Lab route.",
                )
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
            if not self._require_loopback_host():
                return
            path_string = urlsplit(self.path).path
            if path_string.startswith("/api/lab/"):
                api = self._live()
                if api is None:
                    return
                payload = self._read_json()
                if payload is None:
                    return
                try:
                    if path_string == "/api/lab/sessions":
                        response = api.create_session(payload)
                    else:
                        match = re.fullmatch(
                            r"/api/lab/sessions/([^/]+)/([^/]+)",
                            path_string,
                        )
                        if match is None:
                            raise LiveProblem(
                                "NOT_FOUND",
                                "Unknown Live Lab route.",
                                http_status=404,
                            )
                        response = api.command(
                            match.group(1),
                            match.group(2),
                            payload,
                        )
                except LiveProblem as problem:
                    self._live_problem(problem)
                    return
                self._json(response.status, response.payload)
                return
            if path_string != "/api/analyze":
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


def create_server(
    config: FrontendServerConfig,
    *,
    live_orchestrator: LiveLabOrchestrator | None = None,
) -> ThreadingHTTPServer:
    if live_orchestrator is not None and not config.enable_live_lab:
        raise ValueError("live_orchestrator requires enable_live_lab")
    if live_orchestrator is None:
        api = None
    else:
        from ipsec_sentinel.live.api import LiveLabApi

        api = LiveLabApi(live_orchestrator)
    return ThreadingHTTPServer((config.host, config.port), _handler(config, api))


def serve(config: FrontendServerConfig) -> None:
    if config.enable_live_lab:
        from ipsec_sentinel.live.orchestrator import LiveLabOrchestrator
        if config.lab_provider == "gcp":
            from ipsec_sentinel.cloud import (
                GcpLabConfig,
                provider_factory,
                recover_owned_instances,
                session_factory,
            )

            assert config.gcp_config is not None
            cloud_config = GcpLabConfig.load(config.gcp_config)
            orchestrator = LiveLabOrchestrator(
                config.live_runs_dir,
                model_dir=config.model_dir,
                session_factory=session_factory(cloud_config),
                provider_factory=provider_factory(cloud_config),
                startup_recovery=lambda root: recover_owned_instances(root, cloud_config),
                workload_allowlist=frozenset({"icmp", "video"}),
            )
        else:
            orchestrator = LiveLabOrchestrator(
                config.live_runs_dir,
                model_dir=config.model_dir,
            )
    else:
        orchestrator = None
    try:
        server = create_server(config, live_orchestrator=orchestrator)
    except BaseException:
        if orchestrator is not None:
            orchestrator.close()
        raise
    try:
        server.serve_forever()
    finally:
        server.server_close()
        if orchestrator is not None:
            orchestrator.close()
