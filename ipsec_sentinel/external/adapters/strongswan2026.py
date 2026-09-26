from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Iterator

from ipsec_sentinel.external.models import ExternalSession


@dataclass(frozen=True)
class ProtocolExperiment:
    run_id: str
    vpn: str
    platform: str
    wifi_band: str
    stage: str
    delay_ms: int | None
    loss_pct: float | None
    mtu: int
    cpu_stress: bool
    duration_sec: int
    evidence_paths: tuple[str, ...]


class StrongSwan2026CatalogAdapter:
    def __init__(self, extracted_root: Path):
        self.extracted_root = extracted_root

    def read(self) -> tuple[ProtocolExperiment, ...]:
        records: list[ProtocolExperiment] = []
        for metadata_path in sorted(self.extracted_root.glob("*/metadata.json")):
            raw = json.loads(metadata_path.read_text(encoding="utf-8"))
            records.append(
                ProtocolExperiment(
                    run_id=str(raw["run_id"]),
                    vpn=str(raw["vpn"]),
                    platform=str(raw["client_role"]),
                    wifi_band=str(raw["wifi_band"]),
                    stage=str(raw["stage"]),
                    delay_ms=None if raw["delay_ms"] is None else int(raw["delay_ms"]),
                    loss_pct=None if raw["loss_pct"] is None else float(raw["loss_pct"]),
                    mtu=int(raw["mtu"]),
                    cpu_stress=bool(raw["cpu_stress"]),
                    duration_sec=int(raw["duration_sec"]),
                    evidence_paths=tuple(
                        sorted(path.name for path in metadata_path.parent.iterdir() if path.is_file())
                    ),
                )
            )
        return tuple(records)

    def iter_sessions(self, *, limit: int | None = None) -> Iterator[ExternalSession]:
        del limit
        return iter(())
