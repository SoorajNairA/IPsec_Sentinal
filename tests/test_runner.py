import unittest

from ipsec_sentinel.runner import ORDERED_STAGES, execute_ordered_stages, run_cleanup_steps


class RunnerOrderTest(unittest.TestCase):
    def test_cleanup_attempts_every_step_after_an_earlier_failure(self) -> None:
        observed: list[str] = []

        def failing_capture() -> None:
            observed.append("capture")
            raise RuntimeError("tcpdump already failed")

        with self.assertRaisesRegex(RuntimeError, "capture_stop"):
            run_cleanup_steps(
                (
                    ("capture_stop", failing_capture),
                    ("log_copy", lambda: observed.append("logs")),
                    ("daemon_stop", lambda: observed.append("daemons")),
                    ("topology_reset", lambda: observed.append("topology")),
                )
            )

        self.assertEqual(observed, ["capture", "logs", "daemons", "topology"])

    def actions(self, observed: list[str], fail_at: str | None = None):
        actions = {}
        for stage in ORDERED_STAGES:
            def action(name=stage):
                observed.append(name)
                if name == fail_at:
                    raise RuntimeError(f"injected {name}")
            actions[stage] = action
        return actions

    def test_executes_exact_secure_baseline_order(self) -> None:
        observed: list[str] = []
        records = execute_ordered_stages(self.actions(observed))

        self.assertEqual(tuple(observed), ORDERED_STAGES)
        self.assertTrue(all(record.status == "PASS" for record in records))
        self.assertLess(observed.index("capture_start"), observed.index("initiate"))
        self.assertLess(observed.index("icmp"), observed.index("pfs_rekey"))
        self.assertLess(observed.index("pfs_rekey"), observed.index("capture_stop"))

    def test_every_failure_stops_that_layer_and_still_cleans_up(self) -> None:
        for failed_stage in ORDERED_STAGES[:-1]:
            with self.subTest(stage=failed_stage):
                observed: list[str] = []
                with self.assertRaisesRegex(RuntimeError, f"injected {failed_stage}"):
                    execute_ordered_stages(self.actions(observed, failed_stage))
                self.assertEqual(observed[-1], "cleanup")
                self.assertNotIn(
                    ORDERED_STAGES[ORDERED_STAGES.index(failed_stage) + 1],
                    observed[:-1],
                )

    def test_interrupt_is_retained_as_interrupted_stage(self) -> None:
        observed: list[str] = []
        actions = self.actions(observed)
        actions["initiate"] = lambda: (_ for _ in ()).throw(KeyboardInterrupt())
        with self.assertRaises(KeyboardInterrupt) as caught:
            execute_ordered_stages(actions)
        records = caught.exception.stage_records
        self.assertEqual(records[-2].status, "INTERRUPTED")
        self.assertEqual(records[-1].name, "cleanup")


if __name__ == "__main__":
    unittest.main()
