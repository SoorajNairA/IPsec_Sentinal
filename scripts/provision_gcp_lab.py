from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import tempfile

from ipsec_sentinel.cloud.config import GcpLabConfig
from ipsec_sentinel.cloud.gcloud import GcloudClient
from ipsec_sentinel.cloud.manifest import (
    APPROVED_MANIFEST,
    command_digest,
    render_creation_commands,
    render_post_provision_commands,
)


def _journal(path: Path, purpose: str) -> None:
    records = []
    if path.is_file():
        value = json.loads(path.read_text(encoding="utf-8"))
        records = value if isinstance(value, list) else []
    records.append({"purpose": purpose, "status": "SUCCEEDED"})
    path.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Provision the approved GCP lab after command approval")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--approval-digest", required=True)
    parser.add_argument("--journal", type=Path, required=True)
    args = parser.parse_args(argv)
    config = GcpLabConfig.load(args.config)
    creation = render_creation_commands(APPROVED_MANIFEST, config.source_cidr)
    post = render_post_provision_commands(APPROVED_MANIFEST)
    digest = command_digest((*creation, *post))
    if args.approval_digest != digest:
        raise SystemExit("approval digest does not match the exact current command set")
    client = GcloudClient(config)
    for command in creation:
        client.run(command.args, timeout=600)
        _journal(args.journal, command.purpose)

    repository = Path(__file__).resolve().parent.parent
    with tempfile.TemporaryDirectory(prefix="ipsec-sentinel-provision-") as directory:
        staging = Path(directory)
        secrets = staging / "secrets"
        secrets.mkdir(mode=0o700)
        for source, name in (
            (config.psk_file, "psk"),
            (config.control_token_file, "control-token"),
            (config.tls_cert_file, "endpoint.crt"),
            (config.tls_key_file, "endpoint.key"),
        ):
            shutil.copy2(source, secrets / name)
        for scenario, instance in APPROVED_MANIFEST.instance_by_scenario.items():
            client.run(("compute", "instances", "start", instance, f"--zone={config.zone}"), timeout=300)
            client.run(
                (
                    "compute", "scp", "--recurse",
                    str(repository / "ipsec_sentinel"), str(repository / "deploy"),
                    f"{instance}:/tmp/ipsec-sentinel-bundle", f"--zone={config.zone}",
                ),
                timeout=600,
            )
            client.run(
                (
                    "compute", "scp", "--recurse", str(secrets),
                    f"{instance}:/tmp/ipsec-sentinel-secrets", f"--zone={config.zone}",
                ),
                timeout=300,
            )
            client.run(
                (
                    "compute", "ssh", instance, f"--zone={config.zone}",
                    "--command=sudo /bin/sh /tmp/ipsec-sentinel-bundle/deploy/gcp/bootstrap.sh " + scenario,
                ),
                timeout=900,
            )
            client.run(("compute", "instances", "stop", instance, f"--zone={config.zone}"), timeout=300)
            _journal(args.journal, f"provision {scenario}")
    for command in post:
        client.run(command.args, timeout=120)
        _journal(args.journal, command.purpose)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
