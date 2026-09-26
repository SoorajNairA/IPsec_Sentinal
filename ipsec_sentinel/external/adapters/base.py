from __future__ import annotations

from typing import Iterator, Protocol

from ipsec_sentinel.external.models import ExternalSession


class ExternalAdapter(Protocol):
    def iter_sessions(self, *, limit: int | None = None) -> Iterator[ExternalSession]: ...
