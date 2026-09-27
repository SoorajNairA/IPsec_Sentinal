from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
import os
from pathlib import Path
import sys
from typing import Iterator, Sequence

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ipsec_sentinel.artifacts import write_json_atomic
from ipsec_sentinel.frontend.bridge import analyze_for_frontend


DEMO_SCHEMA_ID = "ipsec-sentinel.frontend-demos/v1"
DEMO_VERSION = "1.0"


@dataclass(frozen=True)
class DemoSource:
    demo_id: str
    label: str
    description: str
    run_id: str
    capture_name: str


DEMOS = (
    DemoSource(
        "secure-baseline",
        "Secure Baseline",
        "IKEv2 with AES-256-GCM and independently observed CHILD_SA PFS rekey evidence.",
        "run_000001",
        "full-evidence.pcap",
    ),
    DemoSource(
        "aes128-gcm",
        "AES-128-GCM",
        "A genuine AES-128-GCM session with the same protected topology and PFS policy.",
        "run_000043",
        "full-evidence.pcap",
    ),
    DemoSource(
        "aes256-cbc",
        "AES-256-CBC + SHA-256",
        "A genuine CBC/HMAC session retaining establishment, ESP, and rekey evidence.",
        "run_000085",
        "full-evidence.pcap",
    ),
    DemoSource(
        "no-pfs",
        "PFS Disabled",
        "A controlled AES-256-GCM session with observed CHILD_SA PFS disabled.",
        "run_000127",
        "full-evidence.pcap",
    ),
    DemoSource(
        "video-traffic",
        "Video Traffic Intelligence",
        "An ESP-only workload window analyzed by the retained encrypted-traffic model.",
        "run_000013",
        "encrypted.pcap",
    ),
)


@contextmanager
def _working_directory(path: Path) -> Iterator[None]:
    previous = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


def _digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def generate_demos(
    *,
    dataset_root: Path,
    model_dir: Path,
    output: Path,
    analyzer_commit: str,
) -> dict[str, object]:
    dataset_root = dataset_root.resolve(strict=True)
    model_dir = model_dir.resolve(strict=True)
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    entries: list[dict[str, object]] = []

    for source in DEMOS:
        relative_run = Path("runs") / source.run_id
        relative_capture = relative_run / source.capture_name
        capture = dataset_root / relative_capture
        if not capture.is_file():
            raise FileNotFoundError(f"missing genuine demo capture: {relative_capture.as_posix()}")

        # Analyze from the dataset root so the public result records stable,
        # machine-independent provenance rather than an operator's absolute path.
        with _working_directory(dataset_root):
            envelope = analyze_for_frontend(
                relative_capture,
                model_dir=model_dir,
                evidence_dir=relative_run,
            )
        analysis = envelope["analysis"]
        if analysis["summary"]["status"] != "COMPLETE":
            raise RuntimeError(
                f"demo analysis failed for {source.demo_id}: {analysis['summary']['message']}"
            )

        demo_dir = output / source.demo_id
        analysis_path = demo_dir / "analysis.json"
        xray_path = demo_dir / "xray.json"
        write_json_atomic(analysis_path, analysis)
        write_json_atomic(xray_path, envelope["xray"])
        entries.append(
            {
                "id": source.demo_id,
                "label": source.label,
                "description": source.description,
                "source": {
                    "run_id": source.run_id,
                    "capture": source.capture_name,
                },
                "analysis_path": f"/demos/{source.demo_id}/analysis.json",
                "xray_path": f"/demos/{source.demo_id}/xray.json",
                "sha256": {
                    "analysis": _digest(analysis_path),
                    "xray": _digest(xray_path),
                },
            }
        )

    manifest: dict[str, object] = {
        "schema_id": DEMO_SCHEMA_ID,
        "version": DEMO_VERSION,
        "analyzer_commit": analyzer_commit,
        "generation_command": (
            "python scripts/generate_frontend_demos.py "
            "--dataset-root ${DATASET_ROOT} --model-dir ${MODEL_DIR} "
            "--output frontend/public/demos --analyzer-commit " + analyzer_commit
        ),
        "demos": entries,
    }
    write_json_atomic(output / "manifest.json", manifest)
    return manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate genuine IPsec Sentinel browser demos.")
    parser.add_argument("--dataset-root", required=True, type=Path)
    parser.add_argument("--model-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--analyzer-commit", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    manifest = generate_demos(
        dataset_root=args.dataset_root,
        model_dir=args.model_dir,
        output=args.output,
        analyzer_commit=args.analyzer_commit,
    )
    print(f"Generated {len(manifest['demos'])} genuine demos in {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
