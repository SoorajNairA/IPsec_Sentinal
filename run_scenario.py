from __future__ import annotations

import argparse

from ipsec_sentinel.runner import run_secure_baseline


def main() -> int:
    parser = argparse.ArgumentParser(description="Run an IPsec Sentinel scenario")
    parser.add_argument("scenario", choices=("secure-baseline",))
    parser.add_argument(
        "--keep-lab",
        action="store_true",
        help="leave the four network namespaces in place after the run",
    )
    arguments = parser.parse_args()
    return run_secure_baseline(arguments.scenario, keep_lab=arguments.keep_lab)


if __name__ == "__main__":
    raise SystemExit(main())
