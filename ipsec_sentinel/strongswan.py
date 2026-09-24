from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from time import monotonic, sleep
from typing import TextIO
import os
import re
import signal
import subprocess

from ipsec_sentinel.command import run_checked


IKE_PROPOSAL = "aes256gcm16-prfsha384-ecp384"
ESP_PROPOSAL = "aes256gcm16-ecp384"
LAB_SECRET = "0x5d2f1fb8d6f16c4c03b43242a236c980fed7f25af725e590eafed2e38178ed50"


@dataclass(frozen=True)
class GatewayFiles:
    name: str
    namespace: str
    strongswan: Path
    swanctl: Path
    socket: Path
    pid: Path
    log: Path

    @property
    def vici_uri(self) -> str:
        return f"unix://{self.socket}"


@dataclass(frozen=True)
class RekeyEvidence:
    attempted: bool
    completed: bool
    before_sas: dict[str, str]
    after_sas: dict[str, str]
    log_segment: str


@dataclass(frozen=True)
class _GatewaySpec:
    name: str
    namespace: str
    local_address: str
    remote_address: str
    local_id: str
    remote_id: str
    local_ts: str
    remote_ts: str


GATEWAYS = (
    _GatewaySpec(
        "gateway-a", "ips-gwa", "192.0.2.1", "192.0.2.2",
        "gateway-a", "gateway-b", "10.10.0.0/24", "10.20.0.0/24",
    ),
    _GatewaySpec(
        "gateway-b", "ips-gwb", "192.0.2.2", "192.0.2.1",
        "gateway-b", "gateway-a", "10.20.0.0/24", "10.10.0.0/24",
    ),
)


class StrongSwanPair:
    def __init__(
        self,
        log: TextIO,
        *,
        timeout: float = 10,
        euid: Callable[[], int] = os.geteuid,
    ) -> None:
        self.log = log
        self.timeout = timeout
        self._euid = euid
        self.files: dict[str, GatewayFiles] = {}
        self._processes: dict[str, subprocess.Popen[str]] = {}
        self._stdout_files: dict[str, TextIO] = {}

    def render_configs(
        self,
        run_dir: Path,
        *,
        runtime_root: Path | None = None,
    ) -> dict[str, GatewayFiles]:
        runtime_root = runtime_root or Path("/run/ipsec-sentinel") / run_dir.name
        rendered: dict[str, GatewayFiles] = {}
        for spec in GATEWAYS:
            config_dir = run_dir / "runtime" / spec.name
            config_dir.mkdir(parents=True, exist_ok=True)
            runtime_dir = runtime_root / spec.name
            files = GatewayFiles(
                name=spec.name,
                namespace=spec.namespace,
                strongswan=config_dir / "strongswan.conf",
                swanctl=config_dir / "swanctl.conf",
                socket=runtime_dir / "charon.vici",
                pid=runtime_dir / "charon.pid",
                log=runtime_dir / "charon.log",
            )
            files.strongswan.write_text(_strongswan_config(files), encoding="utf-8")
            files.swanctl.write_text(_swanctl_config(spec), encoding="utf-8")
            rendered[spec.name] = files
        self.files = rendered
        return rendered

    def start(self, run_dir: Path) -> None:
        self._require_root()
        if self._processes:
            raise RuntimeError("strongSwan pair already started")
        runtime_root = Path("/run/ipsec-sentinel") / run_dir.name
        self.render_configs(run_dir, runtime_root=runtime_root)
        try:
            for spec in GATEWAYS:
                files = self.files[spec.name]
                files.socket.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                os.chmod(files.socket.parent, 0o700)
                output_path = run_dir / "runtime" / spec.name / "charon-stdout.log"
                output = output_path.open("w", encoding="utf-8")
                self._stdout_files[spec.name] = output
                environment = os.environ.copy()
                environment["STRONGSWAN_CONF"] = str(files.strongswan.resolve())
                process = subprocess.Popen(
                    ["ip", "netns", "exec", spec.namespace, "charon-systemd"],
                    stdout=output,
                    stderr=subprocess.STDOUT,
                    text=True,
                    env=environment,
                )
                self._processes[spec.name] = process
                files.pid.write_text(f"{process.pid}\n", encoding="ascii")
                self._wait_for_socket(spec.name)
        except BaseException:
            self.stop()
            raise

    def load(self) -> dict[str, str]:
        return {
            name: self._swanctl(name, "--load-all", "--file", str(files.swanctl)).stdout
            for name, files in self.files.items()
        }

    def initiate(self) -> str:
        return self._swanctl(
            "gateway-a", "--initiate", "--child", "protected-nets"
        ).stdout

    def list_sas(self) -> dict[str, str]:
        return {
            name: self._swanctl(name, "--list-sas", "--raw").stdout
            for name in self.files
        }

    def rekey(self) -> RekeyEvidence:
        before = self.list_sas()
        log_path = self.files["gateway-a"].log
        offset = log_path.stat().st_size if log_path.exists() else 0
        self._swanctl("gateway-a", "--rekey", "--child", "protected-nets")
        deadline = monotonic() + self.timeout
        after = before
        completed = False
        while monotonic() < deadline:
            after = self.list_sas()
            completed = all(
                "state=INSTALLED" in after.get(gateway, "")
                and _spis(after.get(gateway, ""))
                and _spis(after.get(gateway, "")) != _spis(before.get(gateway, ""))
                for gateway in ("gateway-a", "gateway-b")
            )
            if completed:
                break
            sleep(0.1)
        segment = ""
        if log_path.exists():
            with log_path.open("rb") as log_file:
                log_file.seek(offset)
                segment = log_file.read().decode("utf-8", errors="replace")
        return RekeyEvidence(True, completed, before, after, segment)

    def stop(self) -> None:
        for name, process in tuple(self._processes.items()):
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=self.timeout)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=self.timeout)
            self._processes.pop(name, None)
        for output in self._stdout_files.values():
            output.close()
        self._stdout_files.clear()
        runtime_dirs: set[Path] = set()
        for files in self.files.values():
            runtime_dirs.add(files.socket.parent)
            files.socket.unlink(missing_ok=True)
            files.pid.unlink(missing_ok=True)
            files.log.unlink(missing_ok=True)
        for directory in sorted(runtime_dirs, key=lambda path: len(path.parts), reverse=True):
            try:
                directory.rmdir()
            except OSError:
                pass
        for parent in {directory.parent for directory in runtime_dirs}:
            try:
                parent.rmdir()
            except OSError:
                pass

    def _swanctl(self, name: str, operation: str, *arguments: str):
        if name not in self.files:
            raise RuntimeError("strongSwan pair has not been configured")
        files = self.files[name]
        return run_checked(
            ["swanctl", operation, "--uri", files.vici_uri, *arguments],
            self.timeout,
            self.log,
        )

    def _wait_for_socket(self, name: str) -> None:
        files = self.files[name]
        process = self._processes[name]
        deadline = monotonic() + self.timeout
        while monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(f"{name} charon exited before VICI became ready")
            if files.socket.exists():
                return
            sleep(0.05)
        raise TimeoutError(f"{name} VICI socket did not appear before timeout")

    def _require_root(self) -> None:
        if self._euid() != 0:
            raise PermissionError("strongSwan lifecycle requires root")


def _strongswan_config(files: GatewayFiles) -> str:
    return f"""charon {{
    load_modular = yes
    plugins {{
        include /etc/strongswan.d/charon/*.conf
        vici {{
            load = yes
            socket = {files.vici_uri}
        }}
    }}
    filelog {{
        lab {{
            path = {files.log}
            append = no
            flush_line = yes
            ike_name = yes
            default = 1
            ike = 2
            chd = 2
            cfg = 2
            knl = 2
            net = 2
        }}
    }}
}}
charon-systemd {{
    journal {{
        default = -1
    }}
}}
"""


def _swanctl_config(spec: _GatewaySpec) -> str:
    return f"""connections {{
    secure-baseline {{
        version = 2
        local_addrs = {spec.local_address}
        remote_addrs = {spec.remote_address}
        proposals = {IKE_PROPOSAL}
        mobike = no
        encap = no
        local {{
            auth = psk
            id = {spec.local_id}
        }}
        remote {{
            auth = psk
            id = {spec.remote_id}
        }}
        children {{
            protected-nets {{
                local_ts = {spec.local_ts}
                remote_ts = {spec.remote_ts}
                mode = tunnel
                esp_proposals = {ESP_PROPOSAL}
                start_action = none
            }}
        }}
    }}
}}
secrets {{
    ike-baseline {{
        id-a = gateway-a
        id-b = gateway-b
        secret = \"{LAB_SECRET}\"
    }}
}}
"""


def _spis(text: str) -> frozenset[str]:
    return frozenset(re.findall(r"spi-(?:in|out)=([0-9a-fA-F]+)", text))
