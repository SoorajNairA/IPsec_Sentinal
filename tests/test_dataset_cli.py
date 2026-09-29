from contextlib import redirect_stdout
from io import StringIO
from types import SimpleNamespace
import unittest

from ipsec_sentinel.dataset.cli import build_parser, main


def passing_summary():
    return SimpleNamespace(
        dataset_name="test", planned_runs=1, successful_runs=1, failed_runs=0,
        incomplete_runs=0, training_ready_runs=1, class_distribution={"icmp": 1},
        supervised_ready_runs=1, ood_ready_runs=0,
        total_esp_packets=10, total_capture_bytes=100, total_duration_seconds=1.0,
        failures_by_class={},
    )


class DatasetCliTest(unittest.TestCase):
    def test_list_traffic_prints_exact_supported_classes(self) -> None:
        output = StringIO()
        with redirect_stdout(output):
            code = main(["list-traffic"])
        self.assertEqual(code, 0)
        self.assertEqual(
            output.getvalue().splitlines(),
            ["email", "file_transfer", "icmp", "messaging", "video", "voip", "web"],
        )

    def test_generate_passes_resume_to_orchestrator(self) -> None:
        observed: list[tuple[str, bool]] = []
        output = StringIO()
        with redirect_stdout(output):
            code = main(
                ["generate", "configs/smoke-v1.yaml", "--resume"],
                generate=lambda path, resume: observed.append((str(path), resume))
                or passing_summary(),
            )
        self.assertEqual(code, 0)
        self.assertEqual(observed, [("configs/smoke-v1.yaml", True)])

    def test_validate_return_code_and_interrupt(self) -> None:
        report = SimpleNamespace(
            passed=False, manifest_readable=True, valid_runs=0, failed_runs=1,
            incomplete_runs=0, errors=("bad capture",),
        )
        with redirect_stdout(StringIO()):
            self.assertEqual(main(["validate", "dataset/x"], validate=lambda path: report), 1)
            self.assertEqual(
                main(
                    ["generate", "configs/smoke-v1.yaml"],
                    generate=lambda path, resume: (_ for _ in ()).throw(KeyboardInterrupt()),
                ),
                130,
            )

    def test_invalid_traffic_choice_fails_parser(self) -> None:
        with self.assertRaises(SystemExit):
            main(["run", "--traffic", "dns"])

    def test_run_parser_accepts_every_supervised_class_and_allowlisted_scenario(self) -> None:
        parser = build_parser()
        for traffic in (
            "icmp", "web", "video", "voip", "email", "messaging",
            "file_transfer",
        ):
            for scenario in (
                "secure-baseline", "aes128-gcm", "aes256-cbc", "no-pfs"
            ):
                args = parser.parse_args(
                    ["run", "--traffic", traffic, "--scenario", scenario]
                )
                self.assertEqual((args.traffic, args.scenario), (traffic, scenario))


if __name__ == "__main__":
    unittest.main()
