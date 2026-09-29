from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import subprocess
from time import monotonic
from typing import Callable, Sequence

from ipsec_sentinel.cloud.config import GcpLabConfig


class GcloudCommandError(RuntimeError):
    def __init__(self, code: str, message: str, *, stderr: str = "") -> None:
        super().__init__(message)
        self.code = code
        self.stderr = stderr


@dataclass(frozen=True)
class CommandReceipt:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float


Runner = Callable[..., subprocess.CompletedProcess[str]]


class GcloudClient:
    _VERBS = frozenset({
        "auth", "config", "projects", "services", "compute",
    })

    def __init__(
        self,
        config: GcpLabConfig,
        *,
        runner: Runner = subprocess.run,
        executable: str = "gcloud",
    ) -> None:
        self.config = config
        self._runner = runner
        self.executable = executable

    def argv(self, args: Sequence[str]) -> list[str]:
        normalized = [str(value) for value in args]
        if not normalized or normalized[0] not in self._VERBS:
            raise ValueError("gcloud command is outside the approved verb families")
        if any(not value or "\x00" in value or "\n" in value or "\r" in value for value in normalized):
            raise ValueError("gcloud arguments must be nonempty single-line values")
        command = [
            self.executable,
            "--quiet",
            f"--project={self.config.project_id}",
            "--format=json",
            *normalized,
        ]
        if os.geteuid() == 0:
            return [
                "runuser", "-u", self.config.operator, "--", "env",
                f"HOME={self.config.operator_home}",
                f"CLOUDSDK_CONFIG={self.config.cloudsdk_config}",
                *command,
            ]
        if os.geteuid() != self.config.operator_uid:
            raise PermissionError("gcloud must run as root or the configured operator")
        return command

    def run(self, args: Sequence[str], *, timeout: float) -> CommandReceipt:
        argv = self.argv(args)
        started = monotonic()
        try:
            completed = self._runner(
                argv,
                text=True,
                capture_output=True,
                check=False,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as error:
            raise GcloudCommandError("GCLOUD_TIMEOUT", "Google Cloud command timed out") from error
        duration = monotonic() - started
        if completed.returncode != 0:
            raise GcloudCommandError(
                "GCLOUD_COMMAND_FAILED",
                "Google Cloud command failed; inspect local provider diagnostics.",
                stderr=completed.stderr,
            )
        return CommandReceipt(
            tuple(argv), completed.returncode, completed.stdout, completed.stderr, duration
        )

    def run_json(self, args: Sequence[str], *, timeout: float) -> object:
        receipt = self.run(args, timeout=timeout)
        try:
            return json.loads(receipt.stdout)
        except json.JSONDecodeError as error:
            raise GcloudCommandError(
                "GCLOUD_INVALID_JSON", "Google Cloud returned invalid JSON"
            ) from error

    def write_redacted_receipt(self, path: Path, receipt: CommandReceipt) -> None:
        payload = {
            "argv": [value for value in receipt.argv if "token" not in value.lower()],
            "returncode": receipt.returncode,
            "duration_seconds": receipt.duration_seconds,
            "stdout": receipt.stdout,
            "stderr": receipt.stderr,
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
