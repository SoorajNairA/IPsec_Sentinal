from __future__ import annotations

import argparse
import http.client
import json
from pathlib import Path
import time

from ipsec_sentinel.artifacts import write_json_atomic


def execute_plan(plan: dict[str, object]) -> list[dict[str, object]]:
    required = {"server_ip", "port", "timeout_seconds", "requests"}
    if set(plan) != required or not isinstance(plan["requests"], list):
        raise ValueError("malformed HTTP client plan")
    connection = http.client.HTTPConnection(
        str(plan["server_ip"]),
        int(plan["port"]),
        timeout=float(plan["timeout_seconds"]),
    )
    results: list[dict[str, object]] = []
    try:
        for request in plan["requests"]:
            if not isinstance(request, dict):
                raise ValueError("malformed HTTP request")
            started = time.monotonic_ns()
            connection.request("GET", str(request["path"]))
            response = connection.getresponse()
            body = response.read()
            result = {
                "path": request["path"],
                "status": response.status,
                "bytes": len(body),
                "duration_ns": time.monotonic_ns() - started,
            }
            results.append(result)
            if response.status != 200 or len(body) != int(request["expected_bytes"]):
                raise RuntimeError(f"invalid HTTP response: {result}")
            time.sleep(float(request["think_seconds"]))
    finally:
        connection.close()
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    plan = json.loads(args.plan.read_text(encoding="utf-8"))
    started = time.monotonic_ns()
    records = execute_plan(plan)
    duration_seconds = (time.monotonic_ns() - started) / 1_000_000_000
    write_json_atomic(
        args.output, {"records": records, "duration_seconds": duration_seconds}
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
