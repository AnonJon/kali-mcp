"""Shared subprocess executor with timeout, sanitization, and output cleaning."""

from __future__ import annotations

import asyncio
import json
import os
import re
import shlex
import tempfile
from dataclasses import dataclass
from typing import Sequence

ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]|\x1b\].*?\x07|\r")
DANGEROUS_PATTERNS = re.compile(r"[;&|`$]|\$\(|>\s*/")

DEFAULT_TIMEOUT = 300
MAX_OUTPUT_SIZE = 100_000  # chars; truncate stdout/stderr beyond this


@dataclass
class ExecResult:
    """Structured result from a subprocess execution."""

    stdout: str
    stderr: str
    exit_code: int
    timed_out: bool = False
    command: str = ""

    def to_dict(self) -> dict:
        d: dict = {"exit_code": self.exit_code}
        if self.stdout:
            d["stdout"] = self.stdout
        if self.stderr:
            d["stderr"] = self.stderr
        if self.timed_out:
            d["timed_out"] = True
            d["message"] = f"Command timed out after execution"
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


def strip_ansi(text: str) -> str:
    """Remove ANSI escape codes and carriage returns."""
    return ANSI_ESCAPE_RE.sub("", text)


def _truncate(text: str, limit: int = MAX_OUTPUT_SIZE) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n\n... [truncated {len(text) - limit} chars]"


def sanitize_input(value: str, allow_shell_chars: bool = False) -> str:
    """Sanitize user input to prevent injection.

    Strips leading/trailing whitespace. Unless allow_shell_chars is True,
    raises ValueError if dangerous shell metacharacters are detected.
    """
    value = value.strip()
    if not allow_shell_chars and DANGEROUS_PATTERNS.search(value):
        raise ValueError(
            f"Input contains dangerous shell characters: {value!r}. "
            "Use execute_command for raw shell access."
        )
    return value


def build_command(binary: str, args: Sequence[str]) -> list[str]:
    """Build a command list from binary and arguments, filtering empty strings."""
    return [binary] + [a for a in args if a]


async def run_command(
    cmd: list[str],
    *,
    timeout: int = DEFAULT_TIMEOUT,
    stdin_data: str | None = None,
    env: dict[str, str] | None = None,
    workdir: str | None = None,
) -> ExecResult:
    """Execute a command asynchronously with timeout and output cleaning."""
    merged_env = None
    if env:
        merged_env = {**os.environ, **env}

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE if stdin_data else asyncio.subprocess.DEVNULL,
            env=merged_env,
            cwd=workdir,
        )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(input=stdin_data.encode() if stdin_data else None),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return ExecResult(
                stdout="",
                stderr=f"Process killed after {timeout}s timeout",
                exit_code=-1,
                timed_out=True,
                command=shlex.join(cmd),
            )

        stdout = _truncate(strip_ansi(stdout_bytes.decode("utf-8", errors="replace")))
        stderr = _truncate(strip_ansi(stderr_bytes.decode("utf-8", errors="replace")))

        return ExecResult(
            stdout=stdout,
            stderr=stderr,
            exit_code=proc.returncode or 0,
            command=shlex.join(cmd),
        )

    except FileNotFoundError:
        return ExecResult(
            stdout="",
            stderr=f"Binary not found: {cmd[0]}",
            exit_code=127,
            command=shlex.join(cmd),
        )
    except Exception as e:
        return ExecResult(
            stdout="",
            stderr=f"Execution error: {e}",
            exit_code=1,
            command=shlex.join(cmd),
        )


async def run_shell(
    command: str,
    *,
    timeout: int = DEFAULT_TIMEOUT,
    workdir: str | None = None,
) -> ExecResult:
    """Execute a raw shell command via /bin/sh."""
    try:
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=workdir,
        )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return ExecResult(
                stdout="",
                stderr=f"Process killed after {timeout}s timeout",
                exit_code=-1,
                timed_out=True,
                command=command,
            )

        stdout = _truncate(strip_ansi(stdout_bytes.decode("utf-8", errors="replace")))
        stderr = _truncate(strip_ansi(stderr_bytes.decode("utf-8", errors="replace")))

        return ExecResult(
            stdout=stdout,
            stderr=stderr,
            exit_code=proc.returncode or 0,
            command=command,
        )

    except Exception as e:
        return ExecResult(
            stdout="",
            stderr=f"Execution error: {e}",
            exit_code=1,
            command=command,
        )


def write_temp_file(content: str, suffix: str = ".txt") -> str:
    """Write content to a temporary file and return the path."""
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return path
