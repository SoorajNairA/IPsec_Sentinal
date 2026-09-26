from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from io import StringIO
import json
import unittest

from ipsec_sentinel.ml.cli import main
from ipsec_sentinel.ml.inference import predict_pcap
from ipsec_sentinel.ml.train import train_and_export
from tests.pcap_helpers import ethernet_ipv4, write_pcap
from tests.test_ml_training import write_training_table


class MlInferenceTest(unittest.TestCase):
    def test_predicts_strict_esp_and_labels_raw_low_confidence(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            features, split = write_training_table(root)
            trained = train_and_export(features, split, root / "model", seed=9)
            pcap = root / "encrypted.pcap"
            write_pcap(
                pcap,
                [
                    (1_000_000_000, ethernet_ipv4("192.0.2.1", "192.0.2.2", 50, b"a" * 66)),
                    (1_100_000_000, ethernet_ipv4("192.0.2.2", "192.0.2.1", 50, b"b" * 66)),
                ],
            )

            prediction = predict_pcap(
                pcap, trained.output_dir, low_confidence_threshold=1.1
            )
            output = StringIO()
            with redirect_stdout(output):
                code = main(
                    ["predict", str(pcap), "--model-dir", str(trained.output_dir),
                     "--low-confidence-threshold", "1.1"]
                )
            cli_prediction = json.loads(output.getvalue())

        self.assertIn(prediction["inferred_class"], ("icmp", "web", "video"))
        self.assertEqual(prediction["evidence_type"], "AI-INFERRED")
        self.assertEqual(prediction["confidence_kind"], "raw_predict_proba")
        self.assertTrue(prediction["low_confidence"])
        self.assertIn("does not decrypt", prediction["interpretation"])
        self.assertEqual(prediction["feature_schema_version"],
                         "ipsec-sentinel.esp-session-features/v1")
        self.assertEqual(code, 0)
        self.assertEqual(cli_prediction["inferred_class"], prediction["inferred_class"])


if __name__ == "__main__":
    unittest.main()
