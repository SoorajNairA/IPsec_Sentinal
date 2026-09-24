from __future__ import annotations

from pathlib import Path
from time import monotonic, sleep
from typing import TextIO
import os
import re
import signal
import subprocess

from ipsec_sentinel.models import CaptureEvidence


CAPTURE_FILTER = (
    "host 192.0.2.1 and host 192.0.2.2 and "
    "(udp port 500 or udp port 4500 or ip proto 50)"
)
AUDIT_FILTER = (
    "(host 192.0.2.1 and host 192.0.2.2 and "
    "(udp port 500 or udp port 4500 or ip proto 50)) or "
    "(icmp and (net 10.10.0.0/24 or net 10.20.0.0/24))"
)


class CaptureValidationError(ValueError):
    """Raised when a saved PCAP does not prove the secure baseline."""


class CaptureSession:
    def __init__(
        self,
        pcap_path: Path,
        log_path: Path,
        *,
        namespace: str = "ips-gwa",
        interface: str = "wan0",
        timeout: float = 5,
        drain_seconds: float = 0.25,
        capture_filter: str = CAPTURE_FILTER,
    ) -> None:
        self.pcap_path = pcap_path
        self.log_path = log_path
        self.namespace = namespace
        self.interface = interface
        self.timeout = timeout
        self.drain_seconds = drain_seconds
        self.capture_filter = capture_filter
        self._process: subprocess.Popen[str] | None = None
        self._log: TextIO | None = None

    @property
    def pid(self) -> int | None:
        return self._process.pid if self._process is not None else None

    def start(self) -> int:
        if os.geteuid() != 0:
            raise PermissionError("packet capture requires root")
        if self._process is not None:
            raise RuntimeError("packet capture already started")
        self.pcap_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.pcap_path.unlink(missing_ok=True)
        self._log = self.log_path.open("w", encoding="utf-8")
        self._process = subprocess.Popen(
            [
                "ip",
                "netns",
                "exec",
                self.namespace,
                "tcpdump",
                "--immediate-mode",
                "-U",
                "-n",
                "-i",
                self.interface,
                "-w",
                str(self.pcap_path),
                self.capture_filter,
            ],
            stdout=subprocess.DEVNULL,
            stderr=self._log,
            text=True,
        )
        deadline = monotonic() + self.timeout
        while monotonic() < deadline:
            if self._process.poll() is not None:
                self._close_log()
                raise RuntimeError("tcpdump exited before capture became ready")
            if self.pcap_path.exists() and self.pcap_path.stat().st_size >= 24:
                return self._process.pid
            sleep(0.05)
        self._process.kill()
        self._process.wait(timeout=self.timeout)
        self._close_log()
        raise TimeoutError("tcpdump did not create a PCAP header before timeout")

    def stop(self) -> None:
        if self._process is None:
            return
        process = self._process
        if process.poll() is None:
            sleep(self.drain_seconds)
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=self.timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=self.timeout)
                self._close_log()
                self._process = None
                raise TimeoutError("tcpdump did not stop after SIGINT")
        returncode = process.returncode
        self._close_log()
        self._process = None
        if returncode != 0:
            raise RuntimeError(f"tcpdump exited with status {returncode}")
        validate_capture_log(self.log_path)

    def _close_log(self) -> None:
        if self._log is not None:
            self._log.close()
            self._log = None


def validate_pcap(
    path: Path,
    peers: tuple[str, str],
    started_at: float,
    ended_at: float,
) -> CaptureEvidence:
    if started_at > ended_at:
        raise CaptureValidationError("invalid capture time window")
    if not path.is_file() or path.stat().st_size == 0:
        raise CaptureValidationError("PCAP is missing or empty")

    packets = _read_packets(path, started_at, ended_at)

    if not packets:
        raise CaptureValidationError("PCAP has no packets in the expected run window")

    def matches_peers(line: str) -> bool:
        return peers[0] in line and peers[1] in line

    ike_packets = sum("isakmp:" in line and matches_peers(line) for line in packets)
    esp_packets = sum("ESP(" in line and matches_peers(line) for line in packets)
    natt_packets = sum(".4500" in line and matches_peers(line) for line in packets)
    cleartext_packets = sum(
        "ICMP" in line and ("10.10." in line or "10.20." in line)
        for line in packets
    )
    outer_protocol_packets = sum(
        "isakmp:" in line or "ESP(" in line for line in packets
    )

    if natt_packets:
        raise CaptureValidationError(f"NAT-T traffic present: {natt_packets} UDP/4500 packets")
    if cleartext_packets:
        raise CaptureValidationError(
            f"protected cleartext traffic present: {cleartext_packets} ICMP packets"
        )
    if outer_protocol_packets and ike_packets + esp_packets == 0:
        raise CaptureValidationError(
            f"IKE/ESP packets do not match expected peer pair {peers[0]} and {peers[1]}"
        )
    if ike_packets == 0:
        raise CaptureValidationError("IKE packets are missing")
    if esp_packets == 0:
        raise CaptureValidationError("ESP packets are missing")

    return CaptureEvidence(
        pcap=path.name,
        packet_count=len(packets),
        ike_packets=ike_packets,
        esp_packets=esp_packets,
        natt_packets=natt_packets,
        cleartext_packets=cleartext_packets,
    )


def validate_wire_cleartext(
    gateway_a_path: Path,
    gateway_b_path: Path,
    *,
    started_at: float,
    ended_at: float,
) -> int:
    a_packets = _read_packets(gateway_a_path, started_at, ended_at)
    b_packets = _read_packets(gateway_b_path, started_at, ended_at)
    for name, packets in (("gateway-a", a_packets), ("gateway-b", b_packets)):
        peer_matched = [
            packet
            for packet in packets
            if "192.0.2.1" in packet and "192.0.2.2" in packet
        ]
        if not any("isakmp:" in packet for packet in peer_matched) or not any(
            "ESP(" in packet for packet in peer_matched
        ):
            raise CaptureValidationError(
                f"{name} cleartext audit is missing peer-matched outer IKE/ESP observations"
            )
    a_signatures = {_icmp_signature(packet) for packet in a_packets}
    b_signatures = {_icmp_signature(packet) for packet in b_packets}
    a_signatures.discard(None)
    b_signatures.discard(None)
    correlated = a_signatures & b_signatures
    if correlated:
        raise CaptureValidationError(
            f"protected cleartext ICMP appeared on both transit endpoints: {len(correlated)} packets"
        )
    return 0


def validate_capture_log(path: Path) -> None:
    if not path.is_file():
        raise CaptureValidationError(f"tcpdump log is missing: {path}")
    text = path.read_text(encoding="utf-8", errors="replace")
    match = re.search(r"(\d+) packets? dropped by kernel", text)
    if match is None:
        raise CaptureValidationError(f"tcpdump drop count is missing: {path}")
    dropped = int(match.group(1))
    if dropped:
        raise CaptureValidationError(
            f"tcpdump reported {dropped} packets dropped by kernel: {path}"
        )


def _read_packets(path: Path, started_at: float, ended_at: float) -> list[str]:
    if not path.is_file() or path.stat().st_size == 0:
        raise CaptureValidationError(f"PCAP is missing or empty: {path}")
    try:
        completed = subprocess.run(
            ["tcpdump", "-tt", "-nn", "-r", str(path)],
            text=True,
            capture_output=True,
            timeout=5,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise CaptureValidationError(f"PCAP reader timed out: {path}") from error
    if completed.returncode != 0:
        raise CaptureValidationError(f"PCAP is empty or unreadable: {completed.stderr.strip()}")
    packets: list[str] = []
    for line in completed.stdout.splitlines():
        fields = line.split(maxsplit=1)
        if len(fields) != 2:
            continue
        try:
            timestamp = float(fields[0])
        except ValueError:
            continue
        if started_at <= timestamp <= ended_at:
            packets.append(fields[1])
    return packets


def _icmp_signature(packet: str) -> tuple[str, str, str, str, str] | None:
    match = re.search(
        r"IP (10\.(?:10|20)\.\d+\.\d+) > (10\.(?:10|20)\.\d+\.\d+): "
        r"ICMP echo (request|reply), id (\d+), seq (\d+)",
        packet,
    )
    if not match:
        return None
    source, destination, kind, identifier, sequence = match.groups()
    if source.split(".")[1] == destination.split(".")[1]:
        return None
    return source, destination, kind, identifier, sequence
