from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from ipsec_sentinel.analyzer.pipeline import analyze_capture


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze an IPsec-related PCAP")
    parser.add_argument("capture", type=Path)
    parser.add_argument("--json", dest="json_path", type=Path)
    parser.add_argument("--model-dir", type=Path, default=Path("model"))
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument("--low-confidence-threshold", type=float, default=0.60)
    return parser


def _value(field: object) -> str:
    if isinstance(field, dict):
        return str(field.get("normalized", field.get("value", "UNKNOWN")))
    return str(field)


def render(result: dict[str, object]) -> str:
    summary = result["summary"]
    protocols = result["protocols"]
    ike = result["ike"]
    pfs = result["pfs"]
    esp = result["esp"]
    traffic = result["traffic_intelligence"]
    score = result["security_score"]
    lines = ["IPsec Sentinel Analysis", "=======================", ""]
    if summary["status"] == "ERROR":
        lines.extend(("Status           ERROR", f"Reason           {summary['message']}"))
        return "\n".join(lines)
    confidence = (
        "UNKNOWN"
        if traffic["raw_confidence"] is None
        else f"{100 * traffic['raw_confidence']:.1f}% raw, uncalibrated"
    )
    lines.extend((
        f"IPsec           {summary['ipsec']}",
        f"IKE             {protocols['ike_version']}",
        f"ESP packets     {esp['packet_count']:,}",
        "",
        f"Encryption      {_value(ike['encryption'])}",
        f"Key Exchange    {_value(ike['dh_group'])}",
        f"PFS             {str(pfs['state']).upper()}",
        f"PFS Evidence    {pfs['provenance']}",
        f"Traffic         {str(traffic['predicted_class']).upper()}",
        f"Confidence      {confidence}",
        "Payload         NOT DECRYPTED",
        "",
        f"Security Score  {score['total']} / {score['maximum']} ({score['assessed_weight']}% assessed)",
        "",
        "Findings", "--------",
    ))
    for finding in result["findings"]:
        lines.append(f"[{finding['severity']}] {finding['title']} ({finding['status']})")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    result = analyze_capture(
        args.capture, model_dir=args.model_dir,
        low_confidence_threshold=args.low_confidence_threshold,
        evidence_dir=args.evidence_dir,
    )
    if args.json_path is not None:
        args.json_path.parent.mkdir(parents=True, exist_ok=True)
        args.json_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(render(result))
    return 0 if result["summary"]["status"] == "COMPLETE" else 2
