import unittest

from ipsec_sentinel.traffic.http_service import deterministic_body
from ipsec_sentinel.traffic.web import resolve_web_plan, validate_web_result


class WebGeneratorTest(unittest.TestCase):
    def test_seed_reproduces_complete_plan_and_other_seeds_vary(self) -> None:
        first = resolve_web_plan(101)
        self.assertEqual(first, resolve_web_plan(101))
        self.assertNotEqual(first, resolve_web_plan(102))
        self.assertGreaterEqual(len(first.requests), 6)
        self.assertTrue(all(request.think_seconds >= 0 for request in first.requests))
        self.assertTrue(20_000 <= first.preferred_port <= 29_999)
        self.assertNotEqual(first.preferred_port, resolve_web_plan(102).preferred_port)

    def test_deterministic_body_has_exact_size(self) -> None:
        first = deterministic_body(seed=101, path="/assets/a.bin", size=4096)
        self.assertEqual(len(first), 4096)
        self.assertEqual(first, deterministic_body(101, "/assets/a.bin", 4096))
        self.assertNotEqual(first, deterministic_body(102, "/assets/a.bin", 4096))

    def test_client_success_without_matching_server_receipts_fails(self) -> None:
        plan = resolve_web_plan(101)
        client = [
            {"path": request.path, "status": 200, "bytes": request.expected_bytes}
            for request in plan.requests
        ]
        validation = validate_web_result(plan, client, client[:-1])
        self.assertFalse(validation.passed)
        self.assertTrue(any("server receipt" in error for error in validation.errors))

    def test_matching_client_and_server_records_pass(self) -> None:
        plan = resolve_web_plan(101)
        records = [
            {"path": request.path, "status": 200, "bytes": request.expected_bytes}
            for request in plan.requests
        ]
        self.assertTrue(validate_web_result(plan, records, records).passed)


if __name__ == "__main__":
    unittest.main()
