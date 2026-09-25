from __future__ import annotations

import argparse
import errno
import socket


def probe(address: str, port: int, protocol: str) -> bool:
    kind = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
    with socket.socket(socket.AF_INET, kind) as candidate:
        try:
            candidate.bind((address, port))
        except OSError as error:
            if error.errno == errno.EADDRINUSE:
                return False
            raise
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--address", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--protocol", choices=("tcp", "udp"), required=True)
    args = parser.parse_args(argv)
    return 0 if probe(args.address, args.port, args.protocol) else 2


if __name__ == "__main__":
    raise SystemExit(main())
