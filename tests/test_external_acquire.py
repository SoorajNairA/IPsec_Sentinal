from __future__ import annotations

from contextlib import contextmanager
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
from threading import Thread
import unittest
from unittest.mock import patch

from ipsec_sentinel.external.acquire import AcquisitionError, acquire_artifact
from ipsec_sentinel.external.registry import (
    ArtifactRecord,
    ChecksumRecord,
    LocalVerification,
)
from ipsec_sentinel.external.storage import ExternalPaths


class _DatasetHandler(BaseHTTPRequestHandler):
    payload = b""
    etag = '"fixture-v1"'
    honor_range = True
    requests: list[dict[str, str | None]] = []

    def log_message(self, *_args):
        pass

    def do_GET(self):
        range_header = self.headers.get("Range")
        if_range = self.headers.get("If-Range")
        type(self).requests.append({"range": range_header, "if_range": if_range})
        body = type(self).payload
        if (
            type(self).honor_range
            and range_header
            and if_range == type(self).etag
        ):
            start = int(range_header.removeprefix("bytes=").removesuffix("-"))
            self.send_response(206)
            self.send_header("Content-Range", f"bytes {start}-{len(body)-1}/{len(body)}")
            body = body[start:]
        else:
            self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("ETag", type(self).etag)
        self.end_headers()
        self.wfile.write(body)


@contextmanager
def _server(payload: bytes, *, etag: str = '"fixture-v1"', honor_range: bool = True):
    handler = type("Handler", (_DatasetHandler,), {})
    handler.payload = payload
    handler.etag = etag
    handler.honor_range = honor_range
    handler.requests = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/artifact", handler
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


def _artifact(url: str, payload: bytes, *, md5: str | None = None) -> ArtifactRecord:
    return ArtifactRecord(
        "fixture",
        "fixture.bin",
        url,
        True,
        len(payload),
        ChecksumRecord("md5", md5 or hashlib.md5(payload).hexdigest()),
        LocalVerification(None, None, None, "not_downloaded"),
    )


class ExternalAcquireTest(unittest.TestCase):
    def _paths(self, temporary: str) -> ExternalPaths:
        return ExternalPaths.create(Path(temporary) / "external")

    def test_download_publishes_only_after_size_md5_and_sha256_pass(self):
        payload = b"authoritative external dataset bytes"
        with tempfile.TemporaryDirectory() as temporary, _server(payload) as (url, _):
            paths = self._paths(temporary)
            receipt = acquire_artifact(_artifact(url, payload), paths)

            self.assertEqual(receipt.observed_size_bytes, len(payload))
            self.assertEqual(receipt.publisher_checksum_result, "matched")
            self.assertEqual(receipt.local_sha256, hashlib.sha256(payload).hexdigest())
            self.assertEqual(receipt.outcome, "downloaded")
            self.assertEqual(receipt.final_path.read_bytes(), payload)
            self.assertFalse(receipt.final_path.with_name("fixture.bin.part").exists())
            saved = json.loads(receipt.receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(saved["local_sha256"], receipt.local_sha256)

    def test_resume_uses_matching_range_and_validator(self):
        payload = b"0123456789" * 100
        with tempfile.TemporaryDirectory() as temporary, _server(payload) as (url, handler):
            paths = self._paths(temporary)
            directory = paths.downloads / "fixture"
            directory.mkdir()
            (directory / "fixture.bin.part").write_bytes(payload[:237])
            (directory / "fixture.bin.part.json").write_text(
                json.dumps({
                    "url": url,
                    "etag": '"fixture-v1"',
                    "last_modified": None,
                    "total_size": len(payload),
                }),
                encoding="utf-8",
            )

            receipt = acquire_artifact(_artifact(url, payload), paths, resume=True)

            self.assertEqual(receipt.final_path.read_bytes(), payload)
            self.assertEqual(handler.requests[0]["range"], "bytes=237-")
            self.assertEqual(handler.requests[0]["if_range"], '"fixture-v1"')

    def test_changed_validator_or_ignored_range_restarts_without_concatenation(self):
        payload = b"new-object" * 80
        for changed_validator, honor_range in ((True, True), (False, False)):
            with self.subTest(changed_validator=changed_validator, honor_range=honor_range):
                etag = '"fixture-v2"' if changed_validator else '"fixture-v1"'
                with tempfile.TemporaryDirectory() as temporary, _server(
                    payload, etag=etag, honor_range=honor_range
                ) as (url, handler):
                    paths = self._paths(temporary)
                    directory = paths.downloads / "fixture"
                    directory.mkdir()
                    (directory / "fixture.bin.part").write_bytes(b"old-prefix")
                    (directory / "fixture.bin.part.json").write_text(
                        json.dumps({
                            "url": url,
                            "etag": '"fixture-v1"',
                            "last_modified": None,
                            "total_size": len(payload),
                        }),
                        encoding="utf-8",
                    )

                    receipt = acquire_artifact(_artifact(url, payload), paths)

                    self.assertEqual(receipt.final_path.read_bytes(), payload)
                    self.assertEqual(handler.requests[0]["range"], "bytes=10-")
                    self.assertEqual(len(receipt.final_path.read_bytes()), len(payload))

    def test_checksum_mismatch_retains_diagnostic_but_not_final_file(self):
        payload = b"downloaded-but-corrupt-for-declared-checksum"
        with tempfile.TemporaryDirectory() as temporary, _server(payload) as (url, _):
            paths = self._paths(temporary)
            artifact = _artifact(url, payload, md5="0" * 32)

            with self.assertRaisesRegex(AcquisitionError, "checksum"):
                acquire_artifact(artifact, paths)

            directory = paths.downloads / "fixture"
            self.assertFalse((directory / "fixture.bin").exists())
            self.assertTrue((directory / "fixture.bin.part").exists())
            diagnostic = json.loads(
                (directory / "fixture.bin.failure.json").read_text(encoding="utf-8")
            )
            self.assertEqual(diagnostic["category"], "checksum")

    def test_verified_rerun_reuses_exact_artifact(self):
        payload = b"stable artifact"
        with tempfile.TemporaryDirectory() as temporary, _server(payload) as (url, handler):
            paths = self._paths(temporary)
            first = acquire_artifact(_artifact(url, payload), paths)
            second = acquire_artifact(_artifact(url, payload), paths)

            self.assertEqual(second.outcome, "reused")
            self.assertEqual(second.local_sha256, first.local_sha256)
            self.assertEqual(len(handler.requests), 1)

    def test_insufficient_space_fails_before_request(self):
        payload = b"requires disk"
        with tempfile.TemporaryDirectory() as temporary, _server(payload) as (url, handler):
            paths = self._paths(temporary)
            with patch("ipsec_sentinel.external.acquire._available_bytes", return_value=0):
                with self.assertRaisesRegex(AcquisitionError, "space"):
                    acquire_artifact(_artifact(url, payload), paths)
            self.assertEqual(handler.requests, [])


if __name__ == "__main__":
    unittest.main()
