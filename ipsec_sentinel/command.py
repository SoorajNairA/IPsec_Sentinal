from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from time import monotonic
from typing import TextIO
import shlex
import subprocess


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float


class CommandFailure(RuntimeError):
    def __init__(
        self,
        argv: list[str],
        *,
        returncode: int | None,
        stdout: str,
        stderr: str,
        timed_out: bool,
    ) -> None:
        self.argv = tuple(argv)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.timed_out = timed_out
        command = shlex.join(argv)
        if timed_out:
            message = f"command timed out: {command}"
        else:
            message = f"command exited with exit {returncode}: {command}"
        super().__init__(message)


def run_checked(
    argv: list[str],
    timeout: float,
    log: TextIO,
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> CommandResult:
    command = shlex.join(argv)
    log.write(f"$ {command}\n")
    log.flush()
    started = monotonic()
    try:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        stdout = _text(error.stdout)
        stderr = _text(error.stderr)
        _write_output(log, stdout, stderr)
        raise CommandFailure(
            argv,
            returncode=None,
            stdout=stdout,
            stderr=stderr,
            timed_out=True,
        ) from error

    duration = monotonic() - started
    _write_output(log, completed.stdout, completed.stderr)
    if completed.returncode != 0:
        raise CommandFailure(
            argv,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            timed_out=False,
        )
    return CommandResult(
        argv=tuple(argv),
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        duration_seconds=duration,
    )


def _write_output(log: TextIO, stdout: str, stderr: str) -> None:
    if stdout:
        log.write(stdout)
    if stderr:
        log.write(stderr)
    log.flush()


def _text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value
