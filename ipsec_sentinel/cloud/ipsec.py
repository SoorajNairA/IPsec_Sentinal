from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import signal
import ssl
import subprocess
import sys
from time import monotonic, sleep, time_ns
from typing import Any, Callable, TextIO
from urllib.request import Request, urlopen

from ipsec_sentinel.artifacts import write_json_atomic, write_text_atomic
from ipsec_sentinel.command import run_checked
from ipsec_sentinel.scenario import Scenario
from ipsec_sentinel.strongswan import GatewayFiles, RekeyEvidence


@dataclass(frozen=True)
class RemoteEvidence:
    swanctl: str
    xfrm: str


class CloudEndpointClient:
    def __init__(
        self,
        run_dir: Path,
        log: TextIO,
        *,
        token_file: Path,
        ca_file: Path,
        session_nonce: str,
        namespace: str = "ips-gwa",
        address: str = "10.20.0.1",
        port: int = 8443,
        timeout: float = 15,
    ) -> None:
        self.run_dir = Path(run_dir)
        self.log = log
        self.token_file = Path(token_file)
        self.ca_file = Path(ca_file)
        self.session_nonce = session_nonce
        self.namespace = namespace
        self.address = address
        self.port = port
        self.timeout = timeout
        self.control_intervals: list[tuple[int, int]] = []
        self._sequence = 0

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, object] | None = None,
    ) -> dict[str, Any]:
        if method not in {"GET", "POST"} or not path.startswith("/v1/"):
            raise ValueError("remote endpoint request is outside the allowlist")
        self._sequence += 1
        request_path = self.run_dir / f"remote-request-{self._sequence:04d}.json"
        response_path = self.run_dir / f"remote-response-{self._sequence:04d}.json"
        write_json_atomic(request_path, {} if payload is None else payload)
        environment = os.environ.copy()
        package_root = str(Path(__file__).resolve().parents[2])
        existing_pythonpath = environment.get("PYTHONPATH")
        environment["PYTHONPATH"] = (
            package_root
            if not existing_pythonpath
            else package_root + os.pathsep + existing_pythonpath
        )
        started = time_ns()
        try:
            run_checked(
                [
                    "ip", "netns", "exec", self.namespace, sys.executable,
                    "-m", "ipsec_sentinel.cloud.ipsec", "request",
                    "--method", method, "--path", path,
                    "--address", self.address, "--port", str(self.port),
                    "--token-file", str(self.token_file), "--ca-file", str(self.ca_file),
                    "--nonce", self.session_nonce, "--payload", str(request_path),
                    "--output", str(response_path), "--timeout", str(self.timeout),
                ],
                self.timeout + 5,
                self.log,
                env=environment,
            )
            value = json.loads(response_path.read_text(encoding="utf-8"))
            if not isinstance(value, dict):
                raise RuntimeError("remote endpoint response is not an object")
            return value
        finally:
            self.control_intervals.append((started, time_ns()))
            request_path.unlink(missing_ok=True)
            response_path.unlink(missing_ok=True)

    def health(self) -> dict[str, Any]:
        return self.request("GET", "/v1/health")

    def evidence(self) -> RemoteEvidence:
        payload = self.request("GET", "/v1/evidence")
        write_text_atomic(
            self.run_dir / "remote-swanctl.txt", str(payload.get("swanctl", ""))
        )
        write_text_atomic(
            self.run_dir / "remote-xfrm-state.txt", str(payload.get("xfrm_state", ""))
        )
        write_text_atomic(
            self.run_dir / "remote-xfrm-policy.txt", str(payload.get("xfrm_policy", ""))
        )
        return RemoteEvidence(
            str(payload.get("swanctl", "")),
            "STATE\n" + str(payload.get("xfrm_state", ""))
            + "POLICY\n" + str(payload.get("xfrm_policy", "")),
        )

    def prepare_video(self, payload: dict[str, object]) -> dict[str, Any]:
        return self.request("POST", "/v1/video/prepare", payload)

    def video_receipts(self) -> list[dict[str, object]]:
        payload = self.request("GET", "/v1/video/receipt")
        receipts = payload.get("receipts", [])
        if not isinstance(receipts, list) or not all(isinstance(item, dict) for item in receipts):
            raise RuntimeError("remote video receipts are malformed")
        return receipts

    def cleanup_video(self) -> None:
        self.request("POST", "/v1/video/cleanup", {})


class CloudStrongSwanClient:
    def __init__(
        self,
        log: TextIO,
        *,
        endpoint_client: CloudEndpointClient,
        psk_file: Path,
        process_observer: Callable[[str, int], None] | None = None,
        timeout: float = 15,
    ) -> None:
        self.log = log
        self.endpoint_client = endpoint_client
        self.psk_file = Path(psk_file)
        self._process_observer = process_observer
        self.timeout = timeout
        self.endpoint: str | None = None
        self.files: dict[str, GatewayFiles] = {}
        self._processes: dict[str, subprocess.Popen[str]] = {}
        self._stdout_files: dict[str, TextIO] = {}
        self._remote_seen = False

    def set_endpoint(self, address: str) -> None:
        self.endpoint = address

    def _render(self, run_dir: Path, scenario: Scenario) -> GatewayFiles:
        if self.endpoint is None:
            raise RuntimeError("cloud endpoint must be configured before strongSwan start")
        config_dir = run_dir / "runtime" / "gateway-a"
        runtime_dir = Path("/run/ipsec-sentinel") / run_dir.name / "gateway-a"
        config_dir.mkdir(parents=True, exist_ok=True)
        runtime_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        files = GatewayFiles(
            "gateway-a", "ips-gwa", config_dir / "strongswan.conf",
            config_dir / "swanctl.conf", runtime_dir / "charon.vici",
            runtime_dir / "charon.pid", runtime_dir / "charon.log",
        )
        files.strongswan.write_text(_strongswan_config(files), encoding="utf-8")
        secret = self.psk_file.read_text(encoding="utf-8").strip()
        if len(secret) < 32:
            raise ValueError("cloud IPsec PSK must contain at least 32 characters")
        files.swanctl.write_text(
            _swanctl_config(self.endpoint, scenario, secret), encoding="utf-8"
        )
        os.chmod(files.strongswan, 0o600)
        os.chmod(files.swanctl, 0o600)
        self.files = {
            "gateway-a": files,
            "gateway-b": GatewayFiles(
                "gateway-b", "remote", config_dir / "remote.conf",
                config_dir / "remote-swanctl.conf", runtime_dir / "remote.vici",
                runtime_dir / "remote.pid", runtime_dir / "remote.log",
            ),
        }
        return files

    def start(self, run_dir: Path, *, scenario: Scenario | None = None) -> None:
        if os.geteuid() != 0:
            raise PermissionError("strongSwan lifecycle requires root")
        if scenario is None:
            raise ValueError("cloud strongSwan requires an explicit scenario")
        files = self._render(run_dir, scenario)
        output = (run_dir / "runtime" / "gateway-a" / "charon-stdout.log").open(
            "w", encoding="utf-8"
        )
        self._stdout_files["gateway-a"] = output
        environment = os.environ.copy()
        environment["STRONGSWAN_CONF"] = str(files.strongswan.resolve())
        try:
            process = subprocess.Popen(
                ["ip", "netns", "exec", "ips-gwa", "charon-systemd"],
                stdout=output, stderr=subprocess.STDOUT, text=True, env=environment,
            )
            self._processes["gateway-a"] = process
            files.pid.write_text(f"{process.pid}\n", encoding="ascii")
            if self._process_observer:
                self._process_observer("strongswan-gateway-a", process.pid)
            deadline = monotonic() + self.timeout
            while monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError("cloud strongSwan client exited before VICI readiness")
                if files.socket.exists():
                    return
                sleep(0.05)
            raise TimeoutError("cloud strongSwan VICI socket did not become ready")
        except BaseException:
            self.stop()
            raise

    def _swanctl(self, operation: str, *arguments: str):
        files = self.files["gateway-a"]
        return run_checked(
            ["swanctl", operation, "--uri", files.vici_uri, *arguments],
            self.timeout, self.log,
        )

    def load(self) -> dict[str, str]:
        files = self.files["gateway-a"]
        return {"gateway-a": self._swanctl("--load-all", "--file", str(files.swanctl)).stdout}

    def initiate(self) -> str:
        return self._swanctl("--initiate", "--child", "protected-nets").stdout

    def list_sas(self) -> dict[str, str]:
        local = self._swanctl("--list-sas", "--raw").stdout
        try:
            remote = self.endpoint_client.evidence()
        except BaseException:
            if self._remote_seen:
                raise
            return {"gateway-a": local, "gateway-b": ""}
        self._remote_seen = True
        return {"gateway-a": local, "gateway-b": remote.swanctl}

    def collect_xfrm(self) -> dict[str, str]:
        state = run_checked(
            ["ip", "netns", "exec", "ips-gwa", "ip", "xfrm", "state"],
            self.timeout, self.log,
        ).stdout
        policy = run_checked(
            ["ip", "netns", "exec", "ips-gwa", "ip", "xfrm", "policy"],
            self.timeout, self.log,
        ).stdout
        remote = self.endpoint_client.evidence()
        return {
            "gateway-a": f"STATE\n{state}POLICY\n{policy}",
            "gateway-b": remote.xfrm,
        }

    def rekey(self) -> RekeyEvidence:
        before = self.list_sas()
        log_path = self.files["gateway-a"].log
        offset = log_path.stat().st_size if log_path.exists() else 0
        self._swanctl("--rekey", "--child", "protected-nets")
        deadline = monotonic() + self.timeout
        after = before
        complete = False
        while monotonic() < deadline:
            after = self.list_sas()
            complete = all(
                _spis(after.get(name, "")) and _spis(after.get(name, "")) != _spis(before.get(name, ""))
                for name in ("gateway-a", "gateway-b")
            )
            if complete:
                break
            sleep(0.2)
        segment = ""
        if log_path.exists():
            with log_path.open("rb") as stream:
                stream.seek(offset)
                segment = stream.read().decode("utf-8", errors="replace")
        return RekeyEvidence(True, complete, before, after, segment)

    def stop(self) -> None:
        errors: list[str] = []
        try:
            self.endpoint_client.cleanup_video()
        except BaseException:
            pass
        for process in tuple(self._processes.values()):
            try:
                if process.poll() is None:
                    process.send_signal(signal.SIGTERM)
                    try:
                        process.wait(timeout=self.timeout)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=self.timeout)
            except BaseException as error:
                errors.append(str(error))
        self._processes.clear()
        for output in self._stdout_files.values():
            output.close()
        self._stdout_files.clear()
        for files in self.files.values():
            files.socket.unlink(missing_ok=True)
            files.pid.unlink(missing_ok=True)
        if errors:
            raise RuntimeError("cloud strongSwan cleanup errors: " + "; ".join(errors))


def _strongswan_config(files: GatewayFiles) -> str:
    return f"""charon {{
    load_modular = yes
    plugins {{ include /etc/strongswan.d/charon/*.conf
        vici {{ load = yes
            socket = {files.vici_uri}
        }}
    }}
    filelog {{ lab {{ path = {files.log}
        append = no
        flush_line = yes
        ike_name = yes
        default = 1
        ike = 2
        chd = 2
        cfg = 2
        knl = 2
        net = 2
    }} }}
}}
charon-systemd {{ journal {{ default = -1 }} }}
"""


def _swanctl_config(endpoint: str, scenario: Scenario, secret: str) -> str:
    return f"""connections {{
    {scenario.id} {{
        version = 2
        local_addrs = 172.31.254.2
        remote_addrs = {endpoint}
        proposals = {scenario.ipsec.ike_proposal}
        mobike = no
        encap = yes
        local {{ auth = psk
            id = gateway-a
        }}
        remote {{ auth = psk
            id = gateway-b
        }}
        children {{ protected-nets {{
            local_ts = 10.10.0.0/24
            remote_ts = 10.20.0.0/24
            mode = tunnel
            esp_proposals = {scenario.ipsec.esp_proposal}
            start_action = none
        }} }}
    }}
}}
secrets {{ ike-cloud {{
    id-a = gateway-a
    id-b = gateway-b
    secret = \"{secret}\"
}} }}
"""


def _spis(text: str) -> frozenset[str]:
    return frozenset(re.findall(r"spi-(?:in|out)=([0-9a-fA-F]+)", text))


def _perform_request(args: argparse.Namespace) -> int:
    token = args.token_file.read_text(encoding="utf-8").strip()
    body = None
    if args.method == "POST":
        body = args.payload.read_bytes()
    request = Request(
        f"https://{args.address}:{args.port}{args.path}",
        data=body,
        method=args.method,
        headers={
            "Authorization": f"Bearer {token}",
            "X-Sentinel-Session": args.nonce,
            "Content-Type": "application/json",
        },
    )
    context = ssl.create_default_context(cafile=str(args.ca_file))
    with urlopen(request, timeout=args.timeout, context=context) as response:
        payload = response.read(1024 * 1024)
    value = json.loads(payload)
    if not isinstance(value, dict):
        raise RuntimeError("endpoint response is not a JSON object")
    write_json_atomic(args.output, value)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    request = subparsers.add_parser("request")
    request.add_argument("--method", choices=("GET", "POST"), required=True)
    request.add_argument("--path", required=True)
    request.add_argument("--address", required=True)
    request.add_argument("--port", type=int, required=True)
    request.add_argument("--token-file", type=Path, required=True)
    request.add_argument("--ca-file", type=Path, required=True)
    request.add_argument("--nonce", required=True)
    request.add_argument("--payload", type=Path, required=True)
    request.add_argument("--output", type=Path, required=True)
    request.add_argument("--timeout", type=float, required=True)
    args = parser.parse_args(argv)
    if args.command == "request":
        return _perform_request(args)
    raise AssertionError("unhandled command")


if __name__ == "__main__":
    raise SystemExit(main())
