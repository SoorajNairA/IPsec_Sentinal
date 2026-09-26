from __future__ import annotations

import argparse
import json
from pathlib import Path

from ipsec_sentinel.ml.dataset import build_feature_dataset
from ipsec_sentinel.ml.inference import predict_pcap
from ipsec_sentinel.ml.split import build_grouped_split
from ipsec_sentinel.ml.train import train_and_export


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python3 -m ipsec_sentinel.ml")
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build")
    build.add_argument("dataset_root", type=Path)
    build.add_argument("output_dir", type=Path)
    split = commands.add_parser("split")
    split.add_argument("features_csv", type=Path)
    split.add_argument("destination", type=Path)
    split.add_argument("--seed", type=int, default=20260926)
    train = commands.add_parser("train")
    train.add_argument("features_csv", type=Path)
    train.add_argument("split_manifest", type=Path)
    train.add_argument("output_dir", type=Path)
    train.add_argument("--seed", type=int, default=20260926)
    predict = commands.add_parser("predict")
    predict.add_argument("pcap", type=Path)
    predict.add_argument("--model-dir", type=Path, default=Path("model"))
    predict.add_argument("--low-confidence-threshold", type=float, default=0.60)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "build":
        result = build_feature_dataset(args.dataset_root, args.output_dir)
        print(json.dumps({"rows": result.row_count,
                          "dataset_sha256": result.dataset_sha256}, sort_keys=True))
    elif args.command == "split":
        result = build_grouped_split(
            args.features_csv, args.destination, seed=args.seed
        )
        print(json.dumps({"sessions": len(result.assignments),
                          "source_sha256": result.source_sha256}, sort_keys=True))
    elif args.command == "train":
        result = train_and_export(
            args.features_csv, args.split_manifest, args.output_dir, seed=args.seed
        )
        print(json.dumps({"selected_model": result.selected_model,
                          "validation_macro_f1": result.validation_macro_f1,
                          "dataset_sha256": result.dataset_sha256}, sort_keys=True))
    else:
        print(
            json.dumps(
                predict_pcap(
                    args.pcap, args.model_dir,
                    low_confidence_threshold=args.low_confidence_threshold,
                ),
                sort_keys=True,
            )
        )
    return 0
