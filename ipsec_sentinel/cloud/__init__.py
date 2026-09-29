"""Narrow Google Cloud Live Lab integration."""

from pathlib import Path
from secrets import token_hex
from time import monotonic, sleep
from typing import TextIO
import json

from ipsec_sentinel.cloud.config import GcpLabConfig
from ipsec_sentinel.cloud.gcloud import GcloudClient
from ipsec_sentinel.cloud.ipsec import CloudEndpointClient, CloudStrongSwanClient
from ipsec_sentinel.cloud.manifest import APPROVED_MANIFEST, GcpDeploymentManifest
from ipsec_sentinel.cloud.topology import CloudClientTopology
from ipsec_sentinel.live.provider import GcpLabProvider
from ipsec_sentinel.session import SecureSession


def session_factory(config: GcpLabConfig):
    def create(run_dir: Path, log: TextIO, **kwargs: object) -> SecureSession:
        observer = kwargs.get("process_observer")
        topology = CloudClientTopology(log, session_id=run_dir.name)
        endpoint = CloudEndpointClient(
            run_dir,
            log,
            token_file=config.control_token_file,
            ca_file=config.tls_ca_file,
            session_nonce=token_hex(32),
            timeout=config.health_timeout_seconds,
        )
        ipsec = CloudStrongSwanClient(
            log,
            endpoint_client=endpoint,
            psk_file=config.psk_file,
            process_observer=observer if callable(observer) else None,
        )
        return SecureSession(
            run_dir,
            log,
            primary_capture_name=str(kwargs.get("primary_capture_name", "full-evidence.pcap")),
            keep_lab=bool(kwargs.get("keep_lab", False)),
            process_observer=observer if callable(observer) else None,
            topology=topology,
            ipsec=ipsec,
            cloud_mode=True,
        )

    return create


def provider_factory(config: GcpLabConfig):
    client = GcloudClient(config)

    def create(session: SecureSession) -> GcpLabProvider:
        return GcpLabProvider(session, config=config, client=client)

    return create


def recover_owned_instances(root_dir: Path, config: GcpLabConfig) -> None:
    """Stop only stale instances carrying an exact Sentinel ownership journal."""
    client = GcloudClient(config)
    allowed = set(config.instance_for(name) for name in (
        "secure-baseline", "aes128-gcm", "aes256-cbc", "no-pfs"
    ))
    for path in sorted(Path(root_dir).glob("SNT-*/cloud-ownership.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        if (
            payload.get("schema") != "ipsec-sentinel.cloud-ownership/v1"
            or payload.get("project") != config.project_id
            or payload.get("zone") != config.zone
            or payload.get("instance") not in allowed
            or payload.get("owned") is not True
        ):
            raise RuntimeError(f"unsafe stale cloud ownership record: {path}")
        instance = str(payload["instance"])
        description = client.run_json(
            ("compute", "instances", "describe", instance, f"--zone={config.zone}"),
            timeout=30,
        )
        if not isinstance(description, dict):
            raise RuntimeError("stale responder description is malformed")
        if description.get("status") != "TERMINATED":
            client.run(
                ("compute", "instances", "stop", instance, f"--zone={config.zone}"),
                timeout=config.stop_timeout_seconds,
            )
            deadline = monotonic() + config.stop_timeout_seconds
            while monotonic() < deadline:
                current = client.run_json(
                    ("compute", "instances", "describe", instance, f"--zone={config.zone}"),
                    timeout=30,
                )
                if isinstance(current, dict) and current.get("status") == "TERMINATED":
                    break
                sleep(2)
            else:
                raise TimeoutError(f"stale responder did not stop: {instance}")
        path.unlink(missing_ok=True)


__all__ = (
    "APPROVED_MANIFEST",
    "GcpDeploymentManifest",
    "GcpLabConfig",
    "provider_factory",
    "recover_owned_instances",
    "session_factory",
)
