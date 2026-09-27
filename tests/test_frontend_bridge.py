from pathlib import Path
import json
import struct
from tempfile import TemporaryDirectory
from threading import Thread
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from ipsec_sentinel.analyzer.pipeline import analyze_capture
from ipsec_sentinel.frontend.bridge import (
    FrontendServerConfig,
    analyze_for_frontend,
    create_server,
    sanitize_capture_filename,
)
from ipsec_sentinel.frontend.xray import build_xray_projection
from tests.pcap_helpers import ethernet_ipv4, write_pcap


def _esp(spi: int, sequence: int, payload_size: int) -> bytes:
    return struct.pack("!II", spi, sequence) + bytes(payload_size)


class XRayProjectionTest(unittest.TestCase):
    def test_projection_uses_real_esp_observations_and_matches_analysis(self) -> None:
        path = Path("tests/fixtures/esp-only.pcap")
        analysis = analyze_capture(path, model_dir=Path("missing-model"))
        projection = build_xray_projection(path)

        self.assertEqual(projection["schema_id"], "ipsec-sentinel.xray/v1")
        self.assertEqual(projection["version"], "1.0")
        self.assertEqual(projection["total_packet_count"], analysis["esp"]["packet_count"])
        self.assertEqual(projection["displayed_packet_count"], len(projection["packets"]))
        self.assertEqual(projection["packets"][0]["relative_time_seconds"], 0.0)
        self.assertIn(projection["packets"][0]["direction"], ("forward", "reverse"))
        self.assertGreater(projection["packets"][0]["length"], 0)

    def test_projection_never_exposes_payload_material(self) -> None:
        projection = build_xray_projection(Path("tests/fixtures/esp-only.pcap"))
        serialized_keys = repr(projection).lower()
        self.assertNotIn("payload", serialized_keys)
        self.assertNotIn("transport_payload", serialized_keys)
        self.assertEqual(
            set(projection["packets"][0]),
            {"relative_time_seconds", "length", "direction"},
        )

    def test_large_projection_is_deterministic_bounded_and_preserves_structure(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "large.pcap"
            packets = []
            for index in range(1_605):
                forward = (index // 100) % 2 == 0
                source, destination = (
                    ("192.0.2.1", "192.0.2.2")
                    if forward else ("192.0.2.2", "192.0.2.1")
                )
                payload_size = 56 + (index % 900)
                if index == 333:
                    payload_size = 20
                if index == 1_111:
                    payload_size = 1_500
                packets.append((
                    1_000_000_000 + index * 1_000_000,
                    ethernet_ipv4(source, destination, 50, _esp(1 if forward else 2, index + 1, payload_size)),
                ))
            write_pcap(path, packets)

            first = build_xray_projection(path, max_points=200)
            second = build_xray_projection(path, max_points=200)

        self.assertEqual(first, second)
        self.assertTrue(first["sampled"])
        self.assertEqual(first["total_packet_count"], 1_605)
        self.assertLessEqual(first["displayed_packet_count"], 200)
        shown = first["packets"]
        self.assertEqual(shown[0]["relative_time_seconds"], 0.0)
        self.assertAlmostEqual(shown[-1]["relative_time_seconds"], 1.604)
        self.assertEqual(min(item["length"] for item in shown), 62)
        self.assertEqual(max(item["length"] for item in shown), 1_542)
        self.assertGreaterEqual(
            sum(left["direction"] != right["direction"] for left, right in zip(shown, shown[1:])),
            15,
        )
        represented_deciles = {
            min(9, int(item["relative_time_seconds"] / 1.605 * 10))
            for item in shown
        }
        self.assertEqual(represented_deciles, set(range(10)))


class FrontendBridgeTest(unittest.TestCase):
    def _start(self, static_dir: Path, *, max_upload_bytes: int = 268_435_456):
        server = create_server(FrontendServerConfig(
            static_dir=static_dir,
            model_dir=Path("missing-model"),
            port=0,
            max_upload_bytes=max_upload_bytes,
        ))
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_address[1]}"

    @staticmethod
    def _json(url: str) -> tuple[int, dict[str, object]]:
        with urlopen(url, timeout=10) as response:
            return response.status, json.loads(response.read())

    @staticmethod
    def _post(url: str, body: bytes, filename: str = "capture.pcap") -> tuple[int, dict[str, object]]:
        request = Request(
            url,
            data=body,
            headers={
                "Content-Type": "application/octet-stream",
                "X-Capture-Filename": filename,
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=10) as response:
                return response.status, json.loads(response.read())
        except HTTPError as error:
            try:
                return error.code, json.loads(error.read())
            finally:
                error.close()

    def test_analysis_function_returns_exact_contract_and_projection_namespaces(self) -> None:
        envelope = analyze_for_frontend(
            Path("tests/fixtures/esp-only.pcap"),
            model_dir=Path("missing-model"),
        )
        self.assertEqual(set(envelope), {"analysis", "xray"})
        self.assertEqual(envelope["analysis"]["schema_id"], "ipsec-sentinel.analysis/v1")
        self.assertEqual(envelope["xray"]["schema_id"], "ipsec-sentinel.xray/v1")

    def test_health_upload_and_spa_fallback(self) -> None:
        with TemporaryDirectory() as directory:
            static = Path(directory)
            (static / "index.html").write_text("<main>Sentinel shell</main>", encoding="utf-8")
            base = self._start(static)
            status, health = self._json(f"{base}/api/health")
            self.assertEqual((status, health["status"]), (200, "ok"))

            capture = Path("tests/fixtures/esp-only.pcap").read_bytes()
            status, envelope = self._post(f"{base}/api/analyze", capture)
            self.assertEqual(status, 200)
            self.assertEqual(envelope["analysis"]["schema_id"], "ipsec-sentinel.analysis/v1")

            with urlopen(f"{base}/analysis/overview", timeout=10) as response:
                self.assertIn(b"Sentinel shell", response.read())

    def test_malformed_pcap_pcapng_and_oversize_are_structured(self) -> None:
        with TemporaryDirectory() as directory:
            static = Path(directory)
            (static / "index.html").write_text("shell", encoding="utf-8")
            base = self._start(static, max_upload_bytes=32)

            status, payload = self._post(f"{base}/api/analyze", b"not a pcap")
            self.assertEqual((status, payload["error"]["code"]), (422, "INVALID_CAPTURE"))

            status, payload = self._post(
                f"{base}/api/analyze",
                b"\x0a\x0d\x0d\x0a" + bytes(28),
            )
            self.assertEqual((status, payload["error"]["code"]), (415, "UNSUPPORTED_PCAPNG"))

            status, payload = self._post(f"{base}/api/analyze", bytes(33))
            self.assertEqual((status, payload["error"]["code"]), (413, "PAYLOAD_TOO_LARGE"))

    def test_non_ipsec_capture_uses_a_stable_safe_error_code(self) -> None:
        result = {
            "analysis": {"summary": {"status": "INCOMPLETE", "ipsec": "NOT_DETECTED", "message": "raw analyzer detail"}},
            "xray": {},
        }
        with TemporaryDirectory() as directory:
            static = Path(directory)
            (static / "index.html").write_text("shell", encoding="utf-8")
            base = self._start(static)
            with patch("ipsec_sentinel.frontend.bridge.analyze_for_frontend", return_value=result):
                status, payload = self._post(f"{base}/api/analyze", b"capture")
        self.assertEqual((status, payload["error"]["code"]), (422, "NO_IPSEC"))
        self.assertNotIn("raw analyzer detail", payload["error"]["message"])

    def test_filename_is_sanitized_and_temporary_upload_is_removed_on_success_and_failure(self) -> None:
        self.assertEqual(sanitize_capture_filename(r"..\..\secret.pcap"), "secret.pcap")
        self.assertEqual(sanitize_capture_filename("../../secret.pcap"), "secret.pcap")

        observed: list[Path] = []

        def fake_analyze(path: Path, **_kwargs: object) -> dict[str, object]:
            observed.append(path)
            self.assertTrue(path.exists())
            if len(observed) == 2:
                raise RuntimeError("controlled failure")
            return {
                "analysis": {
                    "schema_id": "ipsec-sentinel.analysis/v1",
                    "summary": {"status": "COMPLETE"},
                },
                "xray": {},
            }

        with TemporaryDirectory() as directory:
            static = Path(directory)
            (static / "index.html").write_text("shell", encoding="utf-8")
            base = self._start(static)
            with patch("ipsec_sentinel.frontend.bridge.analyze_for_frontend", side_effect=fake_analyze):
                self.assertEqual(self._post(f"{base}/api/analyze", b"first", "../../secret.pcap")[0], 200)
                status, payload = self._post(f"{base}/api/analyze", b"second", "bad.pcap")
                self.assertEqual((status, payload["error"]["code"]), (500, "ANALYZER_FAILURE"))

        self.assertEqual([path.name for path in observed], ["secret.pcap", "bad.pcap"])
        self.assertTrue(all(not path.exists() for path in observed))


if __name__ == "__main__":
    unittest.main()
