from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Mapping, Sequence

from ipsec_sentinel.cloud.config import (
    PROJECT_ID,
    PROJECT_NUMBER,
    REGION,
    SCENARIO_INSTANCES,
    ZONE,
)
from ipsec_sentinel.cloud.gcloud import GcloudClient


NETWORK = "ipsec-sentinel-lab"
SUBNET = "ipsec-sentinel-lab-asia-south1"
SUBNET_CIDR = "10.70.0.0/24"
VPN_TAG = "ipsec-sentinel-vpn"
UDP_FIREWALL = "ipsec-sentinel-ike-natt"
SSH_FIREWALL = "ipsec-sentinel-provision-ssh"
DEPLOYMENT_ID = "gcp-live-lab-v1"


@dataclass(frozen=True)
class CloudCommand:
    purpose: str
    args: tuple[str, ...]

    def shell(self) -> str:
        import shlex

        return shlex.join(("gcloud", f"--project={PROJECT_ID}", *self.args))


@dataclass(frozen=True)
class DeploymentInspection:
    ready: bool
    issues: tuple[str, ...]
    resources_present: tuple[str, ...]


@dataclass(frozen=True)
class GcpDeploymentManifest:
    project_id: str = PROJECT_ID
    project_number: str = PROJECT_NUMBER
    region: str = REGION
    zone: str = ZONE
    network: str = NETWORK
    subnet: str = SUBNET
    subnet_cidr: str = SUBNET_CIDR
    machine_type: str = "e2-micro"
    boot_disk_size_gb: int = 10
    boot_disk_type: str = "pd-balanced"
    image_family: str = "debian-12"
    image_project: str = "debian-cloud"
    deployment_id: str = DEPLOYMENT_ID
    instance_by_scenario: Mapping[str, str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.instance_by_scenario is None:
            object.__setattr__(self, "instance_by_scenario", dict(SCENARIO_INSTANCES))

    @classmethod
    def approved(cls) -> "GcpDeploymentManifest":
        return cls()


APPROVED_MANIFEST = GcpDeploymentManifest.approved()


def render_creation_commands(
    manifest: GcpDeploymentManifest,
    source_cidr: str,
) -> tuple[CloudCommand, ...]:
    commands = [
        CloudCommand(
            "create isolated VPC",
            (
                "compute", "networks", "create", manifest.network,
                "--subnet-mode=custom", "--bgp-routing-mode=regional",
            ),
        ),
        CloudCommand(
            "create Mumbai subnet",
            (
                "compute", "networks", "subnets", "create", manifest.subnet,
                f"--network={manifest.network}", f"--region={manifest.region}",
                f"--range={manifest.subnet_cidr}",
            ),
        ),
        CloudCommand(
            "allow source-restricted IKE and NAT-T",
            (
                "compute", "firewall-rules", "create", UDP_FIREWALL,
                f"--network={manifest.network}", "--direction=INGRESS",
                "--action=ALLOW", "--rules=udp:500,udp:4500",
                f"--source-ranges={source_cidr}", f"--target-tags={VPN_TAG}",
            ),
        ),
        CloudCommand(
            "temporarily allow source-restricted provisioning SSH",
            (
                "compute", "firewall-rules", "create", SSH_FIREWALL,
                f"--network={manifest.network}", "--direction=INGRESS",
                "--action=ALLOW", "--rules=tcp:22",
                f"--source-ranges={source_cidr}", f"--target-tags={VPN_TAG}",
            ),
        ),
    ]
    for scenario, instance in manifest.instance_by_scenario.items():
        commands.append(
            CloudCommand(
                f"create {scenario} responder",
                (
                    "compute", "instances", "create", instance,
                    f"--zone={manifest.zone}",
                    f"--machine-type={manifest.machine_type}",
                    f"--network-interface=network={manifest.network},subnet={manifest.subnet},stack-type=IPV4_ONLY",
                    f"--image-family={manifest.image_family}",
                    f"--image-project={manifest.image_project}",
                    f"--boot-disk-size={manifest.boot_disk_size_gb}GB",
                    f"--boot-disk-type={manifest.boot_disk_type}",
                    "--can-ip-forward", "--no-service-account", "--no-scopes",
                    f"--tags={VPN_TAG}",
                    f"--labels=deployment={manifest.deployment_id},scenario={scenario}",
                    "--no-restart-on-failure",
                ),
            )
        )
        commands.append(
            CloudCommand(
                f"stop {scenario} responder after creation",
                ("compute", "instances", "stop", instance, f"--zone={manifest.zone}"),
            )
        )
    return tuple(commands)


def render_post_provision_commands(
    manifest: GcpDeploymentManifest,
) -> tuple[CloudCommand, ...]:
    return (
        CloudCommand(
            "remove temporary provisioning SSH ingress",
            ("compute", "firewall-rules", "delete", SSH_FIREWALL),
        ),
    )


def render_rollback_commands(
    manifest: GcpDeploymentManifest,
) -> tuple[CloudCommand, ...]:
    commands: list[CloudCommand] = []
    for instance in reversed(tuple(manifest.instance_by_scenario.values())):
        commands.append(
            CloudCommand(
                f"delete responder {instance}",
                (
                    "compute", "instances", "delete", instance,
                    f"--zone={manifest.zone}", "--delete-disks=all",
                ),
            )
        )
    commands.extend(
        (
            CloudCommand("delete temporary SSH rule", ("compute", "firewall-rules", "delete", SSH_FIREWALL)),
            CloudCommand("delete IKE/NAT-T rule", ("compute", "firewall-rules", "delete", UDP_FIREWALL)),
            CloudCommand(
                "delete subnet",
                ("compute", "networks", "subnets", "delete", manifest.subnet, f"--region={manifest.region}"),
            ),
            CloudCommand("delete VPC", ("compute", "networks", "delete", manifest.network)),
        )
    )
    return tuple(commands)


def command_digest(commands: Sequence[CloudCommand]) -> str:
    payload = [
        {"purpose": command.purpose, "args": list(command.args)}
        for command in commands
    ]
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def inspect_deployment(
    client: GcloudClient,
    manifest: GcpDeploymentManifest,
    source_cidr: str,
) -> DeploymentInspection:
    issues: list[str] = []
    present: list[str] = []
    project = client.run_json(
        ("projects", "describe", manifest.project_id), timeout=20
    )
    if not isinstance(project, dict) or str(project.get("projectNumber")) != manifest.project_number:
        issues.append("project number does not match the approved manifest")
    network = client.run_json(
        ("compute", "networks", "describe", manifest.network), timeout=20
    )
    if isinstance(network, dict):
        present.append(manifest.network)
        if network.get("autoCreateSubnetworks") is not False:
            issues.append("VPC is not custom-subnet mode")
    else:
        issues.append("approved VPC is missing")
    subnet = client.run_json(
        (
            "compute", "networks", "subnets", "describe", manifest.subnet,
            f"--region={manifest.region}",
        ),
        timeout=20,
    )
    if isinstance(subnet, dict):
        present.append(manifest.subnet)
        if subnet.get("ipCidrRange") != manifest.subnet_cidr:
            issues.append("subnet CIDR drifted")
    else:
        issues.append("approved subnet is missing")
    instances = client.run_json(
        (
            "compute", "instances", "list", f"--zones={manifest.zone}",
            "--filter=name:(" + " OR ".join(manifest.instance_by_scenario.values()) + ")",
        ),
        timeout=30,
    )
    rows = instances if isinstance(instances, list) else []
    by_name = {str(item.get("name")): item for item in rows if isinstance(item, dict)}
    for scenario, name in manifest.instance_by_scenario.items():
        item = by_name.get(name)
        if item is None:
            issues.append(f"instance missing: {name}")
            continue
        present.append(name)
        status = item.get("status")
        if status != "TERMINATED":
            issues.append(f"instance is not stopped: {name} status={status}")
        labels = item.get("labels") if isinstance(item.get("labels"), dict) else {}
        if labels.get("deployment") != manifest.deployment_id or labels.get("scenario") != scenario:
            issues.append(f"instance labels drifted: {name}")
        machine = str(item.get("machineType", "")).rsplit("/", 1)[-1]
        if machine != manifest.machine_type:
            issues.append(f"instance machine type drifted: {name}")
        if item.get("serviceAccounts"):
            issues.append(f"instance unexpectedly has a service account: {name}")
        if item.get("canIpForward") is not True:
            issues.append(f"instance IP forwarding disabled: {name}")
        tags = item.get("tags") if isinstance(item.get("tags"), dict) else {}
        if tags.get("items") != [VPN_TAG]:
            issues.append(f"instance network tags drifted: {name}")
        interfaces = item.get("networkInterfaces") if isinstance(item.get("networkInterfaces"), list) else []
        if len(interfaces) != 1:
            issues.append(f"instance network interface count drifted: {name}")
        elif not str(interfaces[0].get("network", "")).endswith("/" + manifest.network) or not str(
            interfaces[0].get("subnetwork", "")
        ).endswith("/" + manifest.subnet):
            issues.append(f"instance network attachment drifted: {name}")
        disks = item.get("disks") if isinstance(item.get("disks"), list) else []
        if len(disks) != 1 or str(disks[0].get("diskSizeGb")) != str(manifest.boot_disk_size_gb):
            issues.append(f"instance boot disk drifted: {name}")
        disk = client.run_json(
            ("compute", "disks", "describe", name, f"--zone={manifest.zone}"),
            timeout=20,
        )
        if not isinstance(disk, dict) or not str(disk.get("type", "")).endswith("/" + manifest.boot_disk_type):
            issues.append(f"instance disk type drifted: {name}")
    firewall = client.run_json(
        ("compute", "firewall-rules", "describe", UDP_FIREWALL), timeout=20
    )
    if isinstance(firewall, dict):
        present.append(UDP_FIREWALL)
        allowed = firewall.get("allowed")
        ranges = firewall.get("sourceRanges")
        target_tags = firewall.get("targetTags")
        if (
            ranges != [source_cidr]
            or allowed != [{"IPProtocol": "udp", "ports": ["500", "4500"]}]
            or target_tags != [VPN_TAG]
            or not str(firewall.get("network", "")).endswith("/" + manifest.network)
        ):
            issues.append("IKE/NAT-T firewall rule drifted")
    else:
        issues.append("IKE/NAT-T firewall rule missing")
    return DeploymentInspection(not issues, tuple(sorted(issues)), tuple(sorted(present)))


def assert_approved_command(command: CloudCommand) -> None:
    forbidden_exact = {"0.0.0.0/0", "--rules=all", "--rules=tcp:0-65535"}
    if any(value in forbidden_exact or value.startswith("--service-account=") for value in command.args):
        raise ValueError(f"unsafe cloud command: {command.purpose}")
    approved_names = {
        NETWORK, SUBNET, UDP_FIREWALL, SSH_FIREWALL, VPN_TAG,
        *SCENARIO_INSTANCES.values(),
    }
    if command.args[:3] == ("compute", "instances", "create") and command.args[3] not in approved_names:
        raise ValueError("instance is outside the approved allowlist")
