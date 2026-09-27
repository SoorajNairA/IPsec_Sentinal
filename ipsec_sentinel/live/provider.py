from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Protocol

from ipsec_sentinel.session import SecureSession


VALIDATED_SCENARIOS = frozenset(
    ("secure-baseline", "aes128-gcm", "aes256-cbc", "no-pfs")
)

SCENARIO_NAMES = {
    "secure-baseline": "Secure Baseline",
    "aes128-gcm": "AES-128-GCM",
    "aes256-cbc": "AES-256-CBC + HMAC",
    "no-pfs": "PFS Disabled",
}


@dataclass(frozen=True)
class ProviderEndpoint:
    provider: str
    display_name: str
    address: str
    transport: str
    scenario_id: str
    private: Mapping[str, object] = field(default_factory=dict)

    def to_public_dict(self) -> dict[str, str]:
        return {
            "provider": self.provider,
            "display_name": self.display_name,
            "address": self.address,
            "transport": self.transport,
        }


class LabProvider(Protocol):
    def start_scenario(self, scenario_id: str) -> ProviderEndpoint: ...

    def wait_until_ready(self) -> ProviderEndpoint: ...

    def endpoint(self) -> ProviderEndpoint: ...

    def health(self) -> dict[str, object]: ...

    def stop_scenario(self) -> None: ...


class LocalLabProvider:
    def __init__(self, session: SecureSession) -> None:
        self.session = session
        self._endpoint: ProviderEndpoint | None = None

    def start_scenario(self, scenario_id: str) -> ProviderEndpoint:
        if scenario_id not in VALIDATED_SCENARIOS:
            raise ValueError(f"scenario is not allowlisted: {scenario_id}")
        if self._endpoint is not None:
            raise RuntimeError("local scenario is already started")
        self.session.load_scenario(scenario_id)
        self.session.setup_topology()
        self.session.start_daemons()
        self._endpoint = ProviderEndpoint(
            provider="local",
            display_name=SCENARIO_NAMES[scenario_id],
            address="192.0.2.2",
            transport="native-esp",
            scenario_id=scenario_id,
            private={"gateway_namespace": "ips-gwb"},
        )
        return self._endpoint

    def wait_until_ready(self) -> ProviderEndpoint:
        return self.endpoint()

    def endpoint(self) -> ProviderEndpoint:
        if self._endpoint is None:
            raise RuntimeError("local scenario has not started")
        return self._endpoint

    def health(self) -> dict[str, object]:
        return {"ready": self._endpoint is not None, "provider": "local"}

    def stop_scenario(self) -> None:
        if self._endpoint is None:
            return
        try:
            self.session.cleanup()
        finally:
            self._endpoint = None


class GcpLabProvider:
    """Phase-A boundary only; cloud behavior begins after explicit approval."""

    def start_scenario(self, scenario_id: str) -> ProviderEndpoint:
        del scenario_id
        raise NotImplementedError("GCP provider is reserved for Phase B")

    def wait_until_ready(self) -> ProviderEndpoint:
        raise NotImplementedError("GCP provider is reserved for Phase B")

    def endpoint(self) -> ProviderEndpoint:
        raise NotImplementedError("GCP provider is reserved for Phase B")

    def health(self) -> dict[str, object]:
        return {"ready": False, "provider": "gcp"}

    def stop_scenario(self) -> None:
        raise NotImplementedError("GCP provider is reserved for Phase B")
