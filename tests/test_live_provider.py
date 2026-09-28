from __future__ import annotations

from pathlib import Path
import unittest

from ipsec_sentinel.live.provider import (
    GcpLabProvider,
    LocalLabProvider,
    ProviderEndpoint,
)


class FakeSession:
    def __init__(self) -> None:
        self.calls: list[object] = []

    def load_scenario(self, scenario_id: str) -> object:
        self.calls.append(("load_scenario", scenario_id))
        return object()

    def setup_topology(self) -> None:
        self.calls.append("setup_topology")

    def start_daemons(self) -> None:
        self.calls.append("start_daemons")

    def cleanup(self) -> None:
        self.calls.append("cleanup")


class FailingSession(FakeSession):
    def start_daemons(self) -> None:
        self.calls.append("start_daemons")
        raise RuntimeError("daemon startup failed")


class LocalLabProviderTest(unittest.TestCase):
    def test_start_and_stop_delegate_to_secure_session(self) -> None:
        session = FakeSession()
        provider = LocalLabProvider(session)  # type: ignore[arg-type]

        endpoint = provider.start_scenario("secure-baseline")
        ready = provider.wait_until_ready()

        self.assertEqual(
            session.calls,
            [
                ("load_scenario", "secure-baseline"),
                "setup_topology",
                "start_daemons",
            ],
        )
        self.assertEqual(endpoint, ready)
        self.assertEqual(provider.health(), {"ready": True, "provider": "local"})
        provider.stop_scenario()
        self.assertEqual(session.calls[-1], "cleanup")
        self.assertEqual(provider.health(), {"ready": False, "provider": "local"})

    def test_only_validated_scenarios_are_accepted(self) -> None:
        for scenario_id in (
            "secure-baseline",
            "aes128-gcm",
            "aes256-cbc",
            "no-pfs",
        ):
            with self.subTest(scenario_id=scenario_id):
                provider = LocalLabProvider(FakeSession())  # type: ignore[arg-type]
                self.assertEqual(
                    provider.start_scenario(scenario_id).scenario_id,
                    scenario_id,
                )
        provider = LocalLabProvider(FakeSession())  # type: ignore[arg-type]
        with self.assertRaisesRegex(ValueError, "allowlisted"):
            provider.start_scenario("weak-dh")

    def test_endpoint_public_projection_never_contains_private_configuration(self) -> None:
        endpoint = ProviderEndpoint(
            provider="local",
            display_name="Mystery VPN #03",
            address="192.0.2.2",
            transport="native-esp",
            scenario_id="no-pfs",
            private={"configured_proposal": "aes256gcm16", "pfs": False},
        )

        public = endpoint.to_public_dict()

        self.assertEqual(
            public,
            {
                "provider": "local",
                "display_name": "Mystery VPN #03",
                "address": "192.0.2.2",
                "transport": "native-esp",
            },
        )
        self.assertNotIn("scenario_id", public)
        self.assertNotIn("private", public)

    def test_partial_local_start_can_still_be_stopped_idempotently(self) -> None:
        session = FailingSession()
        provider = LocalLabProvider(session)  # type: ignore[arg-type]
        with self.assertRaisesRegex(RuntimeError, "daemon startup"):
            provider.start_scenario("secure-baseline")
        provider.stop_scenario()
        provider.stop_scenario()
        self.assertEqual(session.calls.count("cleanup"), 1)

    def test_gcp_boundary_has_no_constructor_or_filesystem_side_effect(self) -> None:
        provider = GcpLabProvider()
        before = tuple(Path.cwd().iterdir())
        self.assertEqual(provider.health(), {"ready": False, "provider": "gcp"})
        with self.assertRaisesRegex(NotImplementedError, "Phase B"):
            provider.start_scenario("secure-baseline")
        self.assertEqual(tuple(Path.cwd().iterdir()), before)


if __name__ == "__main__":
    unittest.main()
