from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Protocol, TextIO, runtime_checkable


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
    remote_video_controller: Any | None = None


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
SUPERVISED_CLASS_ALLOWLIST = frozenset(
    {"icmp", "web", "video", "voip", "email", "messaging", "file_transfer"}
)
OOD_CLASS_ALLOWLIST = frozenset({"remote_desktop_like", "database_query_like"})


@dataclass(frozen=True)
class TrafficClassSpec:
    name: str
    factory: GeneratorFactory
    version: str
    known_training_class: bool


_REGISTRY: dict[str, TrafficClassSpec] = {}


def register_generator(
    name: str,
    factory: GeneratorFactory,
    *,
    known_training_class: bool | None = None,
    version: str | None = None,
) -> None:
    if not name or name in _REGISTRY:
        raise ValueError(f"duplicate or empty traffic class: {name}")
    role_was_explicit = known_training_class is not None
    role = True if known_training_class is None else known_training_class
    if role_was_explicit and role and name not in SUPERVISED_CLASS_ALLOWLIST:
        raise ValueError(f"traffic class is not in supervised allowlist: {name}")
    if role_was_explicit and not role and name not in OOD_CLASS_ALLOWLIST:
        raise ValueError(f"traffic class is not in OOD allowlist: {name}")
    resolved_version = version
    if resolved_version is None:
        resolved_version = factory(0).version
    if not resolved_version:
        raise ValueError(f"generator version must be nonempty: {name}")
    _REGISTRY[name] = TrafficClassSpec(
        name=name,
        factory=factory,
        version=resolved_version,
        known_training_class=role,
    )


def traffic_spec(name: str) -> TrafficClassSpec:
    try:
        return _REGISTRY[name]
    except KeyError as error:
        raise ValueError(f"unsupported traffic class: {name}") from error


def traffic_specs() -> tuple[TrafficClassSpec, ...]:
    return tuple(_REGISTRY[name] for name in sorted(_REGISTRY))


def is_supervised_eligible(name: str, known_training_class: bool) -> bool:
    if known_training_class is not True or name not in SUPERVISED_CLASS_ALLOWLIST:
        return False
    try:
        return traffic_spec(name).known_training_class is True
    except ValueError:
        return False


def create_generator(name: str, seed: int) -> TrafficGenerator:
    generator = traffic_spec(name).factory(seed)
    if not isinstance(generator, TrafficGenerator):
        raise TypeError(f"generator does not satisfy TrafficGenerator: {name}")
    return generator


def traffic_classes() -> tuple[str, ...]:
    return tuple(sorted(_REGISTRY))


def generator_versions(names: tuple[str, ...]) -> dict[str, str]:
    return {name: traffic_spec(name).version for name in names}
