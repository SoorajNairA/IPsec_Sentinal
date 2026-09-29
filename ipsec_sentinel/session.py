from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from time import monotonic, sleep, time
from typing import Any, TextIO
import os
import shutil

from ipsec_sentinel.artifacts import write_text_atomic
from ipsec_sentinel.capture import (
    AUDIT_FILTER,
    CaptureSession,
    validate_pcap,
    validate_wire_cleartext,
)
from ipsec_sentinel.command import run_checked
from ipsec_sentinel.evidence import evaluate_pfs, parse_sa
from ipsec_sentinel.models import CaptureEvidence, PfsObservation
from ipsec_sentinel.scenario import Scenario, negotiated_policy, scenario_path
from ipsec_sentinel.strongswan import RekeyEvidence, StrongSwanPair
from ipsec_sentinel.topology import Topology


@dataclass(frozen=True)
class SecureSessionEvidence:
    scenario: Scenario
    scenario_yaml: str
    sas: dict[str, str]
    xfrm: dict[str, str]
    pfs: PfsObservation
    capture: CaptureEvidence
    capture_started_at: float
    capture_ended_at: float
    rekey: RekeyEvidence


def run_cleanup_steps(
    steps: tuple[tuple[str, Callable[[], None]], ...],
) -> None:
    errors: list[str] = []
    for name, action in steps:
        try:
            action()
        except BaseException as error:
            errors.append(f"{name}: {error}")
    if errors:
        raise RuntimeError("cleanup errors: " + "; ".join(errors))


class SecureSession:
    def __init__(
        self,
        run_dir: Path,
        log: TextIO,
        *,
        primary_capture_name: str,
        keep_lab: bool = False,
        process_observer: Callable[[str, int], None] | None = None,
        topology: Any | None = None,
        ipsec: Any | None = None,
        cloud_mode: bool = False,
    ) -> None:
        if primary_capture_name not in ("encrypted.pcap", "full-evidence.pcap"):
            raise ValueError("unsupported primary capture name")
        self.run_dir = run_dir
        self.log = log
        self.keep_lab = keep_lab
        self.topology = topology if topology is not None else Topology(log)
        self.pair = (
            ipsec
            if ipsec is not None
            else StrongSwanPair(log, process_observer=process_observer)
        )
        self.cloud_mode = cloud_mode
        self.primary_destination = run_dir / primary_capture_name
        self.runtime_dir = Path("/run/ipsec-sentinel") / run_dir.name / "capture"
        if cloud_mode:
            self.temporary_pcaps = {"primary": self.runtime_dir / primary_capture_name}
            self.destinations = {"primary": self.primary_destination}
            self.captures = {
                "primary": CaptureSession(
                    self.temporary_pcaps["primary"], run_dir / "tcpdump.log",
                    namespace=getattr(self.topology, "capture_namespace", "ips-gwa"),
                    interface=getattr(self.topology, "capture_interface", "wan0"),
                    capture_filter="udp port 500 or udp port 4500",
                    process_observer=process_observer,
                    process_role="tcpdump-primary",
                )
            }
        else:
            self.temporary_pcaps = {
                "primary": self.runtime_dir / primary_capture_name,
                "gateway-a": self.runtime_dir / "cleartext-audit-gateway-a.pcap",
                "gateway-b": self.runtime_dir / "cleartext-audit-gateway-b.pcap",
            }
            self.destinations = {
                "primary": self.primary_destination,
                "gateway-a": run_dir / "cleartext-audit-gateway-a.pcap",
                "gateway-b": run_dir / "cleartext-audit-gateway-b.pcap",
            }
            self.captures = {
                "primary": CaptureSession(
                    self.temporary_pcaps["primary"], run_dir / "tcpdump.log",
                    process_observer=process_observer,
                    process_role="tcpdump-primary",
                ),
                "gateway-a": CaptureSession(
                    self.temporary_pcaps["gateway-a"],
                    run_dir / "tcpdump-audit-gateway-a.log",
                    capture_filter=AUDIT_FILTER,
                    process_observer=process_observer,
                    process_role="tcpdump-gateway-a",
                ),
                "gateway-b": CaptureSession(
                    self.temporary_pcaps["gateway-b"],
                    run_dir / "tcpdump-audit-gateway-b.log",
                    namespace="ips-gwb",
                    capture_filter=AUDIT_FILTER,
                    process_observer=process_observer,
                    process_role="tcpdump-gateway-b",
                ),
            }
        self.scenario: Scenario | None = None
        self.scenario_yaml = ""
        self.topology_checks = ()
        self.sas: dict[str, str] = {}
        self.xfrm: dict[str, str] = {}
        self.rekey_evidence: RekeyEvidence | None = None
        self.pfs = PfsObservation.not_tested()
        self.capture_evidence: CaptureEvidence | None = None
        self.capture_started_at = 0.0
        self.capture_ended_at = 0.0
        self._captures_finalized = False

    def preflight(self) -> None:
        if os.geteuid() != 0:
            raise PermissionError("IPsec Sentinel must run as Linux root")
        for program in ("ip", "swanctl", "charon-systemd", "tcpdump", "ping"):
            if shutil.which(program) is None:
                raise RuntimeError(f"required program is missing: {program}")
        run_checked(["ip", "xfrm", "state"], 5, self.log)
        run_checked(["ip", "xfrm", "policy"], 5, self.log)
        if not Path("/proc/net/xfrm_stat").is_file():
            raise RuntimeError("kernel XFRM statistics are unavailable")
        if "rfc4106(gcm(aes))" not in Path("/proc/crypto").read_text(encoding="utf-8"):
            raise RuntimeError("kernel RFC 4106 AES-GCM support is unavailable")

    def reset(self) -> None:
        self.topology.reset()

    def load_scenario(self, scenario: str | Path) -> Scenario:
        if isinstance(scenario, Path):
            path = scenario
        else:
            path = scenario_path(scenario)
        self.scenario_yaml = path.read_text(encoding="utf-8")
        self.scenario = Scenario.load(path)
        return self.scenario

    def setup_topology(self) -> None:
        self.topology.setup()
        self.topology_checks = self.topology.verify()
        failures = [check.name for check in self.topology_checks if not check.passed]
        if failures:
            raise RuntimeError(f"topology readback failed: {', '.join(failures)}")

    def start_daemons(self) -> None:
        if self.scenario is None:
            raise RuntimeError("scenario must be loaded before daemon start")
        self.pair.start(self.run_dir, scenario=self.scenario)

    def start_captures(self) -> None:
        self.runtime_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.runtime_dir, 0o700)
        self.capture_started_at = time()
        self._captures_finalized = False
        for capture in self.captures.values():
            capture.start()

    def load_configuration(self) -> dict[str, str]:
        return self.pair.load()

    def initiate(self) -> str:
        return self.pair.initiate()

    def wait_for_sa(self) -> dict[str, str]:
        deadline = monotonic() + 10
        while monotonic() < deadline:
            self.refresh_sas()
            if all(
                parse_sa(self.sas[name]).ike_state == "ESTABLISHED"
                and parse_sa(self.sas[name]).child_state == "INSTALLED"
                for name in ("gateway-a", "gateway-b")
            ):
                return self.sas
            sleep(0.1)
        raise TimeoutError("IKE and CHILD SAs did not become established")

    def refresh_sas(self) -> dict[str, str]:
        self.sas = self.pair.list_sas()
        return self.sas

    def capture_snapshot(self, destination: Path) -> Path:
        primary = self.captures.get("primary")
        if primary is None:
            raise RuntimeError("primary capture is unavailable")
        return primary.snapshot(destination)

    def collect_xfrm(self) -> dict[str, str]:
        collector = getattr(self.pair, "collect_xfrm", None)
        if callable(collector):
            self.xfrm = collector()
            return self.xfrm
        for gateway, namespace in (
            ("gateway-a", "ips-gwa"),
            ("gateway-b", "ips-gwb"),
        ):
            state = run_checked(
                ["ip", "netns", "exec", namespace, "ip", "xfrm", "state"],
                5,
                self.log,
            ).stdout
            policy = run_checked(
                ["ip", "netns", "exec", namespace, "ip", "xfrm", "policy"],
                5,
                self.log,
            ).stdout
            self.xfrm[gateway] = f"STATE\n{state}POLICY\n{policy}"
        return self.xfrm

    def rekey(self) -> PfsObservation:
        if self.scenario is None:
            raise RuntimeError("scenario must be loaded before rekey")
        self.rekey_evidence = self.pair.rekey()
        policy = negotiated_policy(self.scenario)
        child_proposal = "/".join(
            value for value in (policy.esp_encryption, policy.esp_integrity) if value
        )
        self.pfs = evaluate_pfs(
            self.rekey_evidence.before_sas,
            self.rekey_evidence.after_sas,
            self.rekey_evidence.log_segment,
            attempted=self.rekey_evidence.attempted,
            completed=self.rekey_evidence.completed,
            pfs_required=self.scenario.ipsec.pfs,
            expected_child_proposal=child_proposal,
            expected_dh_group=policy.child_dh_group,
        )
        return self.pfs

    def stop_captures(self) -> None:
        if self._captures_finalized:
            return
        run_cleanup_steps(
            tuple((f"{name}_capture", capture.stop) for name, capture in self.captures.items())
        )
        self.capture_ended_at = time()
        for name, destination in self.destinations.items():
            shutil.move(str(self.temporary_pcaps[name]), destination)
        self.runtime_dir.rmdir()
        self._captures_finalized = True

    def validate_captures(self) -> CaptureEvidence:
        if self.cloud_mode:
            from ipsec_sentinel.cloud.natt import validate_cloud_full_capture

            self.capture_evidence = validate_cloud_full_capture(
                self.primary_destination,
                self.capture_peers,
            )
            return self.capture_evidence
        primary = validate_pcap(
            self.primary_destination,
            ("192.0.2.1", "192.0.2.2"),
            self.capture_started_at,
            self.capture_ended_at,
        )
        cleartext = validate_wire_cleartext(
            self.destinations["gateway-a"],
            self.destinations["gateway-b"],
            started_at=self.capture_started_at,
            ended_at=self.capture_ended_at,
        )
        self.capture_evidence = replace(primary, cleartext_packets=cleartext)
        return self.capture_evidence

    @property
    def capture_peers(self) -> tuple[str, str]:
        if self.cloud_mode:
            return tuple(self.topology.capture_peers)
        return ("192.0.2.1", "192.0.2.2")

    @property
    def control_intervals(self) -> tuple[tuple[int, int], ...]:
        endpoint = getattr(self.pair, "endpoint_client", None)
        if endpoint is None:
            return ()
        return tuple(endpoint.control_intervals)

    def evidence(self) -> SecureSessionEvidence:
        if (
            self.scenario is None
            or self.capture_evidence is None
            or self.rekey_evidence is None
        ):
            raise RuntimeError("secure-session evidence is incomplete")
        if not self.sas or not self.xfrm:
            raise RuntimeError("SA or XFRM evidence is incomplete")
        return SecureSessionEvidence(
            self.scenario,
            self.scenario_yaml,
            self.sas,
            self.xfrm,
            self.pfs,
            self.capture_evidence,
            self.capture_started_at,
            self.capture_ended_at,
            self.rekey_evidence,
        )

    def preserve_diagnostics(self) -> None:
        self.run_dir.mkdir(parents=True, exist_ok=True)
        for name, temporary in self.temporary_pcaps.items():
            destination = self.destinations[name]
            if temporary.is_file() and not destination.exists():
                shutil.move(str(temporary), destination)
        for directory in (
            self.runtime_dir,
            self.runtime_dir.parent,
            self.runtime_dir.parent.parent,
        ):
            try:
                directory.rmdir()
            except OSError:
                pass
        for gateway, files in self.pair.files.items():
            if files.log.is_file():
                write_text_atomic(
                    self.run_dir / f"strongswan-{gateway}.log",
                    files.log.read_text(encoding="utf-8", errors="replace"),
                )
        if self.rekey_evidence is not None:
            write_text_atomic(
                self.run_dir / "pfs-rekey.log", self.rekey_evidence.log_segment
            )
            for gateway in ("gateway-a", "gateway-b"):
                write_text_atomic(
                    self.run_dir / f"swanctl-before-rekey-{gateway}.txt",
                    self.rekey_evidence.before_sas[gateway],
                )
                write_text_atomic(
                    self.run_dir / f"swanctl-after-rekey-{gateway}.txt",
                    self.rekey_evidence.after_sas[gateway],
                )

    def cleanup(self) -> None:
        steps: list[tuple[str, Callable[[], None]]] = [
            (
                "capture_stop",
                lambda: run_cleanup_steps(
                    tuple(
                        (f"{name}_capture", capture.stop)
                        for name, capture in self.captures.items()
                    )
                ),
            ),
            ("log_copy", self.preserve_diagnostics),
            ("daemon_stop", self.pair.stop),
        ]
        if not self.keep_lab:
            steps.append(("topology_reset", self.topology.reset))
        run_cleanup_steps(tuple(steps))
