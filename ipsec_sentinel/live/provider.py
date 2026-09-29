from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from time import monotonic, sleep
from typing import Mapping, Protocol

from ipsec_sentinel.artifacts import write_json_atomic

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
        self._owns_resources = False

    def start_scenario(self, scenario_id: str) -> ProviderEndpoint:
        if scenario_id not in VALIDATED_SCENARIOS:
            raise ValueError(f"scenario is not allowlisted: {scenario_id}")
        if self._endpoint is not None:
            raise RuntimeError("local scenario is already started")
        self._owns_resources = True
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
        if not self._owns_resources:
            return
        self.session.cleanup()
        self._endpoint = None
        self._owns_resources = False


class GcpLabProvider:
    """Own one allowlisted GCP responder and the session's local cloud sandbox."""

    READY_MARKER = "IPSEC_SENTINEL_READY"

    def __init__(
        self,
        session: SecureSession | None = None,
        *,
        config: object | None = None,
        client: object | None = None,
        sleeper=sleep,
    ) -> None:
        from ipsec_sentinel.cloud.config import GcpLabConfig
        from ipsec_sentinel.cloud.gcloud import GcloudClient

        if session is None and config is None and client is None:
            self.session = None
            self.config = None
            self.client = None
            self._sleep = sleeper
            self._endpoint = None
            self._scenario_id = None
            self._instance = None
            self._owns_instance = False
            self._local_started = False
            self._ownership_path = Path("cloud-ownership.json")
            return
        if session is None or not isinstance(config, GcpLabConfig) or not isinstance(client, GcloudClient):
            raise TypeError("GcpLabProvider requires validated cloud config and client")
        self.session = session
        self.config = config
        self.client = client
        self._sleep = sleeper
        self._endpoint: ProviderEndpoint | None = None
        self._scenario_id: str | None = None
        self._instance: str | None = None
        self._owns_instance = False
        self._local_started = False
        self._ownership_path = Path(session.run_dir) / "cloud-ownership.json"

    def _describe(self) -> dict[str, object]:
        if self._instance is None:
            raise RuntimeError("cloud scenario has not been selected")
        value = self.client.run_json(
            (
                "compute", "instances", "describe", self._instance,
                f"--zone={self.config.zone}",
            ),
            timeout=30,
        )
        if not isinstance(value, dict):
            raise RuntimeError("Compute Engine instance description is malformed")
        return value

    @staticmethod
    def _public_address(description: Mapping[str, object]) -> str:
        interfaces = description.get("networkInterfaces")
        if not isinstance(interfaces, list) or len(interfaces) != 1:
            raise RuntimeError("responder must have exactly one network interface")
        interface = interfaces[0]
        if not isinstance(interface, Mapping):
            raise RuntimeError("responder network interface is malformed")
        access = interface.get("accessConfigs")
        if not isinstance(access, list) or len(access) != 1 or not isinstance(access[0], Mapping):
            raise RuntimeError("responder must have exactly one ephemeral public address")
        address = access[0].get("natIP")
        if not isinstance(address, str) or not address:
            raise RuntimeError("responder public address is unavailable")
        return address

    def _write_ownership(self, status: str, **extra: object) -> None:
        if self._instance is None or self._scenario_id is None:
            return
        write_json_atomic(
            self._ownership_path,
            {
                "schema": "ipsec-sentinel.cloud-ownership/v1",
                "project": self.config.project_id,
                "zone": self.config.zone,
                "instance": self._instance,
                "scenario_id": self._scenario_id,
                "owned": self._owns_instance,
                "status": status,
                **extra,
            },
        )

    def start_scenario(self, scenario_id: str) -> ProviderEndpoint:
        if self.session is None or self.config is None or self.client is None:
            raise NotImplementedError("GCP provider requires Phase B configuration")
        if scenario_id not in VALIDATED_SCENARIOS:
            raise ValueError(f"scenario is not allowlisted: {scenario_id}")
        if self._instance is not None:
            raise RuntimeError("cloud scenario is already started")
        self._scenario_id = scenario_id
        self._instance = self.config.instance_for(scenario_id)
        from ipsec_sentinel.cloud.manifest import APPROVED_MANIFEST, inspect_deployment

        inspection = inspect_deployment(
            self.client,
            APPROVED_MANIFEST,
            self.config.source_cidr,
        )
        if not inspection.ready:
            raise RuntimeError(
                "approved GCP deployment drift detected: " + "; ".join(inspection.issues)
            )
        description = self._describe()
        if description.get("status") != "TERMINATED":
            self._write_ownership("REFUSED_UNOWNED_RUNNING")
            raise RuntimeError("allowlisted responder was already running and is not owned")
        labels = description.get("labels")
        if not isinstance(labels, Mapping) or labels.get("scenario") != scenario_id:
            raise RuntimeError("responder scenario label does not match the allowlist")
        if labels.get("deployment") != "gcp-live-lab-v1":
            raise RuntimeError("responder deployment label does not match")
        self._owns_instance = True
        self._write_ownership("STARTING")
        try:
            self.client.run(
                (
                    "compute", "instances", "start", self._instance,
                    f"--zone={self.config.zone}",
                ),
                timeout=self.config.startup_timeout_seconds,
            )
        except BaseException:
            self._write_ownership("START_FAILED")
            raise
        self._endpoint = ProviderEndpoint(
            provider="gcp",
            display_name="Google Cloud VPN Lab",
            address="pending",
            transport="natt",
            scenario_id=scenario_id,
            private={"instance": self._instance},
        )
        return self._endpoint

    def wait_until_ready(self) -> ProviderEndpoint:
        if self.session is None or self.config is None or self.client is None:
            raise NotImplementedError("GCP provider requires Phase B configuration")
        if self._endpoint is None or self._instance is None or self._scenario_id is None:
            raise RuntimeError("cloud scenario has not started")
        deadline = monotonic() + self.config.startup_timeout_seconds
        description: dict[str, object] | None = None
        while monotonic() < deadline:
            description = self._describe()
            if description.get("status") == "RUNNING":
                break
            self._sleep(2)
        else:
            raise TimeoutError("cloud responder did not reach RUNNING")
        assert description is not None
        address = self._public_address(description)
        marker_deadline = monotonic() + self.config.health_timeout_seconds
        marker_seen = False
        while monotonic() < marker_deadline:
            serial = self.client.run_json(
                (
                    "compute", "instances", "get-serial-port-output", self._instance,
                    f"--zone={self.config.zone}", "--port=1", "--start=0",
                ),
                timeout=30,
            )
            if isinstance(serial, dict) and self.READY_MARKER in str(serial.get("contents", "")):
                marker_seen = True
                break
            self._sleep(2)
        if not marker_seen:
            raise TimeoutError("cloud responder did not emit its neutral readiness marker")
        topology = getattr(self.session, "topology", None)
        pair = getattr(self.session, "pair", None)
        if not hasattr(topology, "set_endpoint") or not hasattr(pair, "set_endpoint"):
            raise RuntimeError("SecureSession is not configured with cloud adapters")
        topology.set_endpoint(address)
        pair.set_endpoint(address)
        self.session.load_scenario(self._scenario_id)
        self.session.setup_topology()
        self.session.start_daemons()
        self._local_started = True
        self._endpoint = ProviderEndpoint(
            provider="gcp",
            display_name="Google Cloud VPN Lab",
            address=address,
            transport="natt",
            scenario_id=self._scenario_id,
            private={"instance": self._instance},
        )
        self._write_ownership("READY", endpoint=address)
        return self._endpoint

    def endpoint(self) -> ProviderEndpoint:
        if self.session is None:
            raise NotImplementedError("GCP provider requires Phase B configuration")
        if self._endpoint is None:
            raise RuntimeError("cloud scenario has not started")
        return self._endpoint

    def health(self) -> dict[str, object]:
        if self.session is None or self.config is None or self.client is None:
            return {"ready": False, "provider": "gcp"}
        if self._instance is None:
            return {"ready": False, "provider": "gcp"}
        try:
            description = self._describe()
            ready = description.get("status") == "RUNNING"
            if ready and self._local_started:
                endpoint_client = getattr(getattr(self.session, "pair", None), "endpoint_client", None)
                if endpoint_client is not None:
                    ready = bool(endpoint_client.health().get("ready"))
        except BaseException:
            ready = False
        return {"ready": ready, "provider": "gcp"}

    def stop_scenario(self) -> None:
        if self.session is None or self.config is None or self.client is None:
            raise NotImplementedError("GCP provider requires Phase B configuration")
        errors: list[str] = []
        if self._local_started:
            try:
                self.session.cleanup()
            except BaseException as error:
                errors.append(f"local cleanup: {error}")
            self._local_started = False
        if self._owns_instance and self._instance is not None:
            try:
                self.client.run(
                    (
                        "compute", "instances", "stop", self._instance,
                        f"--zone={self.config.zone}",
                    ),
                    timeout=self.config.stop_timeout_seconds,
                )
                deadline = monotonic() + self.config.stop_timeout_seconds
                while monotonic() < deadline:
                    stopped = self._describe()
                    address_released = False
                    try:
                        self._public_address(stopped)
                    except RuntimeError:
                        address_released = True
                    if stopped.get("status") == "TERMINATED" and address_released:
                        break
                    self._sleep(2)
                else:
                    raise TimeoutError("cloud responder did not stop and release its address")
            except BaseException as error:
                self._write_ownership("STOP_FAILED", error_type=type(error).__name__)
                errors.append(f"cloud stop: {error}")
            else:
                self._owns_instance = False
                self._ownership_path.unlink(missing_ok=True)
        self._endpoint = None
        if errors:
            raise RuntimeError("GCP provider cleanup errors: " + "; ".join(errors))
