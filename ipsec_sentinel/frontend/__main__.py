from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from ipsec_sentinel.frontend.bridge import FrontendServerConfig, serve


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Serve the local IPsec Sentinel frontend")
    parser.add_argument("--static-dir", type=Path, default=Path("frontend/dist"))
    parser.add_argument("--model-dir", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8_787)
    parser.add_argument("--max-upload-bytes", type=int, default=268_435_456)
    parser.add_argument("--enable-live-lab", action="store_true")
    parser.add_argument("--live-runs-dir", type=Path, default=Path("runs/live"))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    serve(FrontendServerConfig(
        static_dir=args.static_dir,
        model_dir=args.model_dir,
        port=args.port,
        max_upload_bytes=args.max_upload_bytes,
        enable_live_lab=args.enable_live_lab,
        live_runs_dir=args.live_runs_dir,
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
