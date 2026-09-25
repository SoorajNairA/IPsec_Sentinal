from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json

from ipsec_sentinel.dataset.config import DatasetConfig
from ipsec_sentinel.dataset.models import SEED_DERIVATION_VERSION
from ipsec_sentinel.traffic import register_builtin_generators
from ipsec_sentinel.traffic.base import is_supervised_eligible, traffic_spec


@dataclass(frozen=True)
class MatrixSlot:
    slot_id: str
    ordinal: int
    scenario_id: str
    traffic_class: str
    network_profile: str
    repetition: int


def expand_matrix(
    config: DatasetConfig, generator_versions: dict[str, str]
) -> tuple[MatrixSlot, ...]:
    register_builtin_generators()
    unknown = set(config.traffic_classes) - set(generator_versions)
    if unknown:
        raise ValueError(f"unregistered traffic class: {sorted(unknown)[0]}")
    for name in config.traffic_classes:
        spec = traffic_spec(name)
        if not is_supervised_eligible(name, spec.known_training_class):
            raise ValueError(f"traffic class is not supervised-eligible: {name}")
    slots: list[MatrixSlot] = []
    ordinal = 0
    for scenario_id in config.scenarios:
        for traffic_class in config.traffic_classes:
            for network_profile in config.network_profiles:
                for repetition in range(1, config.runs_per_combination + 1):
                    ordinal += 1
                    slots.append(
                        MatrixSlot(
                            slot_id=f"run_{ordinal:06d}",
                            ordinal=ordinal,
                            scenario_id=scenario_id,
                            traffic_class=traffic_class,
                            network_profile=network_profile,
                            repetition=repetition,
                        )
                    )
    return tuple(slots)


def derive_attempt_seed(base_seed: int, ordinal: int, attempt_number: int) -> int:
    if ordinal < 1 or attempt_number < 1:
        raise ValueError("ordinal and attempt_number must be positive")
    material = (
        f"{SEED_DERIVATION_VERSION}:{base_seed}:{ordinal}:{attempt_number}".encode(
            "ascii"
        )
    )
    return int.from_bytes(hashlib.sha256(material).digest()[:8], "big") & (
        (1 << 63) - 1
    )


def attempt_id(slot_id: str, attempt_number: int) -> str:
    if attempt_number < 1:
        raise ValueError("attempt_number must be positive")
    return slot_id if attempt_number == 1 else f"{slot_id}-attempt{attempt_number:02d}"


def matrix_fingerprint(
    config: DatasetConfig, generator_versions: dict[str, str]
) -> str:
    slots = expand_matrix(config, generator_versions)
    payload = {
        "dataset": {
            "name": config.name,
            "schema_version": config.schema_version,
            "base_seed": config.base_seed,
        },
        "traffic_classes": list(config.traffic_classes),
        "scenarios": list(config.scenarios),
        "network_profiles": list(config.network_profiles),
        "runs_per_combination": config.runs_per_combination,
        "evaluation_ood_classes": list(config.evaluation_ood_classes),
        "evaluation_runs_per_combination": config.evaluation_runs_per_combination,
        "workers": config.workers,
        "retry_failed": config.retry_failed,
        "generator_versions": [
            [name, generator_versions[name]] for name in config.traffic_classes
        ],
        "slots": [asdict(slot) for slot in slots],
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
