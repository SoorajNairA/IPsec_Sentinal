import unittest
from unittest.mock import patch

import ipsec_sentinel.traffic.base as traffic_base
from ipsec_sentinel.traffic.base import (
    OOD_CLASS_ALLOWLIST,
    SUPERVISED_CLASS_ALLOWLIST,
    TrafficContext,
    TrafficGenerator,
    TrafficRunResult,
    TrafficValidation,
    create_generator,
    is_supervised_eligible,
    register_generator,
    traffic_spec,
    traffic_specs,
)


class ExampleGenerator:
    name = "example"
    version = "1"

    def prepare(self, context: TrafficContext) -> None:
        return None

    def run(self, context: TrafficContext) -> TrafficRunResult:
        return TrafficRunResult(metrics={"requests": 1})

    def validate(
        self, context: TrafficContext, result: TrafficRunResult
    ) -> TrafficValidation:
        return TrafficValidation(True, {"requests": 1}, ())

    def cleanup(self, context: TrafficContext) -> None:
        return None

    def metadata(self) -> dict[str, object]:
        return {"generator": self.name, "version": self.version}


class TrafficContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        register_generator("example", lambda seed: ExampleGenerator())

    def test_registry_returns_a_runtime_conforming_generator(self) -> None:
        generator = create_generator("example", seed=7)
        self.assertIsInstance(generator, TrafficGenerator)
        self.assertEqual(generator.metadata()["version"], "1")

    def test_unknown_generator_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported traffic class"):
            create_generator("unknown", seed=7)

    def test_registry_role_is_authoritative_and_dual_selection_fails_closed(self) -> None:
        with patch.dict(traffic_base._REGISTRY, {}, clear=True):
            register_generator(
                "icmp", lambda seed: ExampleGenerator(), known_training_class=True
            )
            register_generator(
                "remote_desktop_like",
                lambda seed: ExampleGenerator(),
                known_training_class=False,
            )

            self.assertTrue(is_supervised_eligible("icmp", True))
            self.assertFalse(is_supervised_eligible("icmp", False))
            self.assertFalse(is_supervised_eligible("remote_desktop_like", True))
            self.assertFalse(
                traffic_spec("remote_desktop_like").known_training_class
            )
            self.assertEqual(
                tuple(spec.name for spec in traffic_specs()),
                ("icmp", "remote_desktop_like"),
            )

    def test_registry_rejects_duplicates_and_invalid_allowlist_roles(self) -> None:
        with patch.dict(traffic_base._REGISTRY, {}, clear=True):
            register_generator(
                "icmp", lambda seed: ExampleGenerator(), known_training_class=True
            )
            with self.assertRaisesRegex(ValueError, "duplicate"):
                register_generator(
                    "icmp", lambda seed: ExampleGenerator(), known_training_class=True
                )
            with self.assertRaisesRegex(ValueError, "supervised allowlist"):
                register_generator(
                    "remote_desktop_like",
                    lambda seed: ExampleGenerator(),
                    known_training_class=True,
                )
            with self.assertRaisesRegex(ValueError, "OOD allowlist"):
                register_generator(
                    "web",
                    lambda seed: ExampleGenerator(),
                    known_training_class=False,
                )

        self.assertEqual(
            SUPERVISED_CLASS_ALLOWLIST,
            frozenset(
                {"icmp", "web", "video", "voip", "email", "messaging", "file_transfer"}
            ),
        )
        self.assertEqual(
            OOD_CLASS_ALLOWLIST,
            frozenset({"remote_desktop_like", "database_query_like"}),
        )


if __name__ == "__main__":
    unittest.main()
