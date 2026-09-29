from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
import os
from pathlib import Path
import pwd
from typing import Any


PROJECT_ID = "ipsec-sentinel"
PROJECT_NUMBER = "429285250074"
REGION = "asia-south1"
ZONE = "asia-south1-a"
SCENARIO_INSTANCES = {
    "secure-baseline": "vpn-secure",
    "aes128-gcm": "vpn-aes128",
    "aes256-cbc": "vpn-cbc",
    "no-pfs": "vpn-no-pfs",
}


class CloudConfigurationError(ValueError):
    pass


def _secure_file(path: Path, *, label: str) -> Path:
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise CloudConfigurationError(f"{label} file does not exist: {resolved}")
    mode = resolved.stat().st_mode & 0o777
    if os.name == "posix" and mode & 0o077:
        raise CloudConfigurationError(f"{label} file must be mode 0600 or stricter")
    return resolved


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise CloudConfigurationError(f"{label} must be an object with string keys")
    return value


@dataclass(frozen=True)
class GcpLabConfig:
    operator: str
    operator_uid: int
    operator_home: Path
    cloudsdk_config: Path
    source_cidr: str
    psk_file: Path
    control_token_file: Path
    tls_ca_file: Path
    tls_cert_file: Path
    tls_key_file: Path
    project_id: str = PROJECT_ID
    project_number: str = PROJECT_NUMBER
    region: str = REGION
    zone: str = ZONE
    startup_timeout_seconds: int = 180
    health_timeout_seconds: int = 60
    stop_timeout_seconds: int = 120
    maximum_runtime_seconds: int = 900

    @classmethod
    def load(cls, path: Path) -> "GcpLabConfig":
        config_path = _secure_file(Path(path), label="cloud config")
        try:
            root = _mapping(json.loads(config_path.read_text(encoding="utf-8")), "config")
        except (OSError, json.JSONDecodeError) as error:
            raise CloudConfigurationError(f"cloud config is not valid JSON: {error}") from error
        allowed = {
            "project_id", "project_number", "region", "zone", "operator",
            "operator_uid", "operator_home", "cloudsdk_config", "source_cidr",
            "psk_file", "control_token_file", "tls_ca_file", "tls_cert_file",
            "tls_key_file",
            "startup_timeout_seconds", "health_timeout_seconds",
            "stop_timeout_seconds", "maximum_runtime_seconds",
        }
        unknown = set(root) - allowed
        missing = allowed - set(root)
        if unknown or missing:
            detail = f"unknown={sorted(unknown)} missing={sorted(missing)}"
            raise CloudConfigurationError(f"cloud config keys do not match schema: {detail}")
        fixed = {
            "project_id": PROJECT_ID,
            "project_number": PROJECT_NUMBER,
            "region": REGION,
            "zone": ZONE,
        }
        for key, expected in fixed.items():
            if root[key] != expected:
                raise CloudConfigurationError(f"{key} must be {expected!r}")
        operator = str(root["operator"])
        try:
            account = pwd.getpwnam(operator)
        except KeyError as error:
            raise CloudConfigurationError(f"operator account does not exist: {operator}") from error
        operator_uid = int(root["operator_uid"])
        operator_home = Path(str(root["operator_home"])).resolve()
        if account.pw_uid != operator_uid or Path(account.pw_dir).resolve() != operator_home:
            raise CloudConfigurationError("operator UID/home do not match the account database")
        sdk = Path(str(root["cloudsdk_config"])).resolve()
        if not sdk.is_dir() or sdk.stat().st_uid != operator_uid:
            raise CloudConfigurationError("Cloud SDK directory is absent or not operator-owned")
        try:
            source = ipaddress.ip_network(str(root["source_cidr"]), strict=True)
        except ValueError as error:
            raise CloudConfigurationError("source_cidr must be a valid network") from error
        if source.version != 4 or source.prefixlen != 32:
            raise CloudConfigurationError("source_cidr must be one public IPv4 /32")
        if not source.network_address.is_global:
            raise CloudConfigurationError("source_cidr must be globally routable")
        timeouts = {
            key: int(root[key])
            for key in (
                "startup_timeout_seconds", "health_timeout_seconds",
                "stop_timeout_seconds", "maximum_runtime_seconds",
            )
        }
        if not 10 <= timeouts["health_timeout_seconds"] <= 180:
            raise CloudConfigurationError("health timeout is outside 10..180 seconds")
        if not 30 <= timeouts["startup_timeout_seconds"] <= 600:
            raise CloudConfigurationError("startup timeout is outside 30..600 seconds")
        if not 30 <= timeouts["stop_timeout_seconds"] <= 300:
            raise CloudConfigurationError("stop timeout is outside 30..300 seconds")
        if not 300 <= timeouts["maximum_runtime_seconds"] <= 1800:
            raise CloudConfigurationError("maximum runtime is outside 300..1800 seconds")
        return cls(
            operator=operator,
            operator_uid=operator_uid,
            operator_home=operator_home,
            cloudsdk_config=sdk,
            source_cidr=str(source),
            psk_file=_secure_file(Path(str(root["psk_file"])), label="PSK"),
            control_token_file=_secure_file(
                Path(str(root["control_token_file"])), label="control token"
            ),
            tls_ca_file=_secure_file(Path(str(root["tls_ca_file"])), label="TLS CA"),
            tls_cert_file=_secure_file(Path(str(root["tls_cert_file"])), label="TLS certificate"),
            tls_key_file=_secure_file(Path(str(root["tls_key_file"])), label="TLS key"),
            **fixed,
            **timeouts,
        )

    def instance_for(self, scenario_id: str) -> str:
        try:
            return SCENARIO_INSTANCES[scenario_id]
        except KeyError as error:
            raise CloudConfigurationError(f"scenario is not allowlisted: {scenario_id}") from error
