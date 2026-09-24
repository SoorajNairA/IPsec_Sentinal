from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol, TextIO, runtime_checkable


@dataclass(frozen=True)
class TrafficContext:
    run_dir: Path
    log: TextIO
    seed: int
    scenario_id: str
    network_profile: str
    client_namespace: str = "ips-client"
    server_namespace: str = "ips-server"
    client_ip: str = "10.10.0.2"
    server_ip: str = "10.20.0.2"


@dataclass(frozen=True)
class TrafficRunResult:
    metrics: dict[str, object]


@dataclass(frozen=True)
class TrafficValidation:
    passed: bool
    evidence: dict[str, object]
    errors: tuple[str, ...]


@runtime_checkable
class TrafficGenerator(Protocol):
    name: str
    version: str

    def prepare(self, context: TrafficContext) -> None: ...

    def run(self, context: TrafficContext) -> TrafficRunResult: ...

    def validate(
        self, context: TrafficContext, result: TrafficRunResult
    ) -> TrafficValidation: ...

    def cleanup(self, context: TrafficContext) -> None: ...

    def metadata(self) -> dict[str, object]: ...


GeneratorFactory = Callable[[int], TrafficGenerator]
_REGISTRY: dict[str, GeneratorFactory] = {}


def register_generator(name: str, factory: GeneratorFactory) -> None:
    if not name or name in _REGISTRY:
        raise ValueError(f"duplicate or empty traffic class: {name}")
    _REGISTRY[name] = factory


def create_generator(name: str, seed: int) -> TrafficGenerator:
    try:
        generator = _REGISTRY[name](seed)
    except KeyError as error:
        raise ValueError(f"unsupported traffic class: {name}") from error
    if not isinstance(generator, TrafficGenerator):
        raise TypeError(f"generator does not satisfy TrafficGenerator: {name}")
    return generator


def traffic_classes() -> tuple[str, ...]:
    return tuple(sorted(_REGISTRY))


def generator_versions(names: tuple[str, ...]) -> dict[str, str]:
    return {name: create_generator(name, seed=0).version for name in names}
