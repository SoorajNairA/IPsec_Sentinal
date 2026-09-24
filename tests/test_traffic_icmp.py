import unittest

from ipsec_sentinel.traffic.icmp import IcmpGenerator, resolve_icmp_plan


class IcmpGeneratorTest(unittest.TestCase):
    def test_same_seed_reproduces_plan_and_different_seed_varies_it(self) -> None:
        self.assertEqual(resolve_icmp_plan(41), resolve_icmp_plan(41))
        plans = {resolve_icmp_plan(seed) for seed in range(41, 51)}
        self.assertGreater(len(plans), 1)
        plan = resolve_icmp_plan(41)
        self.assertIn(plan.count, (5, 7, 9))
        self.assertIn(plan.interval_seconds, (0.1, 0.2, 0.3))
        self.assertIn(plan.payload_bytes, (56, 128, 512))

    def test_validation_requires_every_planned_reply(self) -> None:
        generator = IcmpGenerator(seed=41)
        count = generator.plan.count
        ok = generator.validate_output(
            f"{count} packets transmitted, {count} received, 0% packet loss, time 408ms\n"
        )
        failed = generator.validate_output(
            f"{count} packets transmitted, {count - 1} received, 20% packet loss, time 408ms\n"
        )
        self.assertTrue(ok.passed)
        self.assertFalse(failed.passed)
        self.assertIn("received", failed.errors[0])

    def test_metadata_contains_every_resolved_parameter(self) -> None:
        metadata = IcmpGenerator(seed=41).metadata()
        self.assertEqual(metadata["generator_version"], "1")
        self.assertEqual(
            set(metadata["parameters"]),
            {"count", "interval_seconds", "payload_bytes"},
        )


if __name__ == "__main__":
    unittest.main()
