from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


class ScenarioError(ValueError):
    """Raised when a scenario is outside the supported Phase 1 contract."""


@dataclass(frozen=True)
class IpsecConfig:
    ike_version: int
    mode: str
    ike_proposal: str
    esp_proposal: str
    local_subnet: str
    remote_subnet: str
    transit_subnet: str
    pfs: bool
    ip_version: int


@dataclass(frozen=True)
class TrafficConfig:
    type: str
    count: int


@dataclass(frozen=True)
class CaptureConfig:
    enabled: bool


@dataclass(frozen=True)
class Scenario:
    id: str
    ipsec: IpsecConfig
    traffic: TrafficConfig
    capture: CaptureConfig

    @classmethod
    def load(cls, path: Path) -> "Scenario":
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as error:
            raise ScenarioError(f"scenario: {error}") from error

        root = _mapping(raw, "scenario")
        _require_keys(root, {"id", "ipsec", "traffic", "capture"}, "scenario")
        ipsec = _mapping(root["ipsec"], "ipsec")
        traffic = _mapping(root["traffic"], "traffic")
        capture = _mapping(root["capture"], "capture")

        _require_keys(
            ipsec,
            {
                "ike_version",
                "mode",
                "ike_proposal",
                "esp_proposal",
                "local_subnet",
                "remote_subnet",
                "transit_subnet",
                "pfs",
                "ip_version",
            },
            "ipsec",
        )
        _require_keys(traffic, {"type", "count"}, "traffic")
        _require_keys(capture, {"enabled"}, "capture")

        expected = {
            "id": (root["id"], "secure-baseline"),
            "ike_version": (ipsec["ike_version"], 2),
            "mode": (ipsec["mode"], "tunnel"),
            "ike_proposal": (
                ipsec["ike_proposal"],
                "aes256gcm16-prfsha384-ecp384",
            ),
            "esp_proposal": (ipsec["esp_proposal"], "aes256gcm16-ecp384"),
            "local_subnet": (ipsec["local_subnet"], "10.10.0.0/24"),
            "remote_subnet": (ipsec["remote_subnet"], "10.20.0.0/24"),
            "transit_subnet": (ipsec["transit_subnet"], "192.0.2.0/30"),
            "pfs": (ipsec["pfs"], True),
            "ip_version": (ipsec["ip_version"], 4),
            "traffic.type": (traffic["type"], "icmp"),
            "traffic.count": (traffic["count"], 5),
            "capture.enabled": (capture["enabled"], True),
        }
        for field, (actual, required) in expected.items():
            if actual != required or type(actual) is not type(required):
                raise ScenarioError(
                    f"{field}: expected {required!r}, received {actual!r}"
                )

        return cls(
            id=root["id"],
            ipsec=IpsecConfig(**ipsec),
            traffic=TrafficConfig(**traffic),
            capture=CaptureConfig(**capture),
        )


def _mapping(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ScenarioError(f"{field}: expected a mapping")
    if not all(isinstance(key, str) for key in value):
        raise ScenarioError(f"{field}: all keys must be strings")
    return value


def _require_keys(data: dict[str, Any], allowed: set[str], field: str) -> None:
    unknown = set(data) - allowed
    missing = allowed - set(data)
    if unknown:
        raise ScenarioError(f"{field}: unknown field {sorted(unknown)[0]}")
    if missing:
        raise ScenarioError(f"{field}: missing field {sorted(missing)[0]}")
