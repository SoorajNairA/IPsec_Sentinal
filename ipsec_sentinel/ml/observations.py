from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class PacketObservation(Protocol):
    @property
    def relative_time_seconds(self) -> float: ...

    @property
    def length(self) -> int: ...

    @property
    def direction(self) -> str: ...

