from __future__ import annotations

import argparse
import ipaddress
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ipsec_sentinel.cloud.manifest import (
    APPROVED_MANIFEST,
    assert_approved_command,
    command_digest,
    render_creation_commands,
    render_post_provision_commands,
    render_rollback_commands,
    render_source_update_commands,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render GCP lab commands without executing them")
    parser.add_argument("--source-cidr", required=True)
    parser.add_argument(
        "--update-existing",
        action="store_true",
        help="render only the approved source-/32 update and temporary SSH gate",
    )
    args = parser.parse_args(argv)
    source = ipaddress.ip_network(args.source_cidr, strict=True)
    if source.version != 4 or source.prefixlen != 32 or not source.network_address.is_global:
        parser.error("--source-cidr must be one globally routable IPv4 /32")
    creation = (
        render_source_update_commands(APPROVED_MANIFEST, str(source))
        if args.update_existing
        else render_creation_commands(APPROVED_MANIFEST, str(source))
    )
    post = render_post_provision_commands(APPROVED_MANIFEST)
    for command in (*creation, *post):
        assert_approved_command(command)
    print("CREATION AND POST-PROVISION COMMANDS")
    for index, command in enumerate((*creation, *post), 1):
        print(f"{index:02d}. {command.purpose}\n    {command.shell()}")
    print(f"APPROVAL DIGEST: {command_digest((*creation, *post))}")
    print("\nDESTRUCTIVE ROLLBACK COMMANDS (NOT AUTOMATICALLY APPROVED)")
    for index, command in enumerate(render_rollback_commands(APPROVED_MANIFEST), 1):
        print(f"R{index:02d}. {command.purpose}\n    {command.shell()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
