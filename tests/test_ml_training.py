from pathlib import Path
from tempfile import TemporaryDirectory
import csv
import json
import unittest

import joblib

from ipsec_sentinel.ml.schema import FEATURE_NAMES, FEATURE_SCHEMA_VERSION
from ipsec_sentinel.ml.split import build_grouped_split
from ipsec_sentinel.ml.train import train_and_export


CLASSES = ("icmp", "web", "video")
SCENARIOS = ("secure-baseline", "aes128-gcm")


def write_training_table(root: Path) -> tuple[Path, Path]:
    features = root / "features.csv"
    with features.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(
            output,
            fieldnames=("session_id", "label", "scenario_id", *FEATURE_NAMES),
        )
        writer.writeheader()
        for class_index, label in enumerate(CLASSES, start=1):
            for scenario_index, scenario in enumerate(SCENARIOS, start=1):
                for repetition in range(6):
                    row: dict[str, object] = {
                        "session_id": f"{label}-{scenario}-{repetition}",
                        "label": label,
                        "scenario_id": scenario,
                        **{name: 0.0 for name in FEATURE_NAMES},
                    }
                    row["packet_count"] = class_index * 100 + repetition
                    row["total_bytes"] = class_index * 10_000 + repetition * 10
                    row["size_mean"] = class_index * 300 + scenario_index
                    row["direction_switch_ratio"] = class_index / 10
                    writer.writerow(row)
    split = root / "split.json"
    build_grouped_split(features, split, seed=20260926)
    return features, split


class MlTrainingTest(unittest.TestCase):
    def test_benchmarks_exports_and_serializes_without_metadata_features(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            features, split = write_training_table(root)
            first = train_and_export(features, split, root / "model-a", seed=7)
            second = train_and_export(features, split, root / "model-b", seed=7)
            metrics = json.loads(first.metrics_path.read_text(encoding="utf-8"))
            metadata = json.loads(
                first.training_metadata_path.read_text(encoding="utf-8")
            )
            bundle = joblib.load(first.model_path)
            exported = {
                name: (first.output_dir / name).is_file()
                for name in (
                    "model.joblib", "feature_schema.json", "class_map.json",
                    "metrics.json", "split_manifest.json", "training_metadata.json",
                )
            }

        self.assertEqual(first.selected_model, second.selected_model)
        self.assertEqual(first.validation_macro_f1, second.validation_macro_f1)
        self.assertEqual(
            set(metrics["candidates"]),
            {"random_forest", "extra_trees", "hist_gradient_boosting"},
        )
        self.assertIn("test", metrics)
        self.assertIn("per_scenario", metrics)
        self.assertIn("leave_one_scenario_out", metrics)
        self.assertEqual(metrics["calibration"]["status"], "not_applied")
        self.assertEqual(tuple(bundle["feature_names"]), FEATURE_NAMES)
        self.assertEqual(bundle["feature_schema_version"], FEATURE_SCHEMA_VERSION)
        self.assertEqual(metadata["dataset_sha256"], first.dataset_sha256)
        self.assertRegex(metadata["git_commit_sha"], r"^[0-9a-f]{40}$")
        forbidden = {"session_id", "label", "scenario_id", "seed", "port"}
        self.assertTrue(forbidden.isdisjoint(bundle["feature_names"]))
        for name, present in exported.items():
            self.assertTrue(present, name)


if __name__ == "__main__":
    unittest.main()
