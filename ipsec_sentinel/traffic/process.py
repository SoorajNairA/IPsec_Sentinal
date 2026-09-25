from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path
import subprocess
import sys
import time
from typing import IO, Any

from ipsec_sentinel.traffic.base import TrafficContext


class NamespaceServiceProcess:
    def __init__(
        self,
        context: TrafficContext,
        *,
        module: str,
        arguments: Sequence[str],
        ready_path: Path,
        log_name: str,
        namespace: str | None = None,
        readiness_timeout: float = 10.0,
        stop_timeout: float = 5.0,
        popen_factory: Callable[..., Any] = subprocess.Popen,
    ) -> None:
        self.context = context
        self.module = module
        self.arguments = tuple(arguments)
        self.ready_path = ready_path
        self.log_name = log_name
        self.namespace = namespace or context.server_namespace
        self.readiness_timeout = readiness_timeout
        self.stop_timeout = stop_timeout
        self.popen_factory = popen_factory
        self.process: Any | None = None
        self.output: IO[str] | None = None

    def start(self) -> None:
        if self.process is not None:
            raise RuntimeError("namespace service already started")
        self.ready_path.unlink(missing_ok=True)
        self.output = (self.context.run_dir / self.log_name).open(
            "w", encoding="utf-8"
        )
        argv = [
            "ip", "netns", "exec", self.namespace, sys.executable,
            "-m", self.module, *self.arguments,
        ]
        self.context.log.write("$ " + " ".join(argv) + "\n")
        self.context.log.flush()
        try:
            self.process = self.popen_factory(
                argv, stdout=self.output, stderr=subprocess.STDOUT, text=True
            )
            deadline = time.monotonic() + self.readiness_timeout
            while time.monotonic() < deadline:
                if self.ready_path.is_file():
                    return
                returncode = self.process.poll()
                if returncode is not None:
                    raise RuntimeError(
                        f"namespace service exited with {returncode}: {self.module}"
                    )
                time.sleep(0.05)
            raise TimeoutError(f"namespace service readiness timed out: {self.module}")
        except BaseException:
            self.stop()
            raise

    def stop(self) -> None:
        process, self.process = self.process, None
        try:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=self.stop_timeout)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=self.stop_timeout)
        finally:
            self.ready_path.unlink(missing_ok=True)
            if self.output is not None:
                self.output.close()
                self.output = None
