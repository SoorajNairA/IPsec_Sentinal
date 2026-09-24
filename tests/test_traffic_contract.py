import unittest

from ipsec_sentinel.traffic.base import (
    TrafficContext,
    TrafficGenerator,
    TrafficRunResult,
    TrafficValidation,
    create_generator,
    register_generator,
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


if __name__ == "__main__":
    unittest.main()
