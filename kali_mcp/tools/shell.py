"""Shell tools: execute_command, background_command, check_job, cancel_job."""

from __future__ import annotations

import json
import os
import signal
import uuid

from kali_mcp.executor import run_shell
from kali_mcp.server import mcp

JOBS_DIR = "/opt/workspace/jobs"

_background_jobs: dict[str, dict] = {}


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


@mcp.tool()
async def execute_command(
    command: str,
    timeout: int = 300,
    workdir: str = "/opt/workspace",
) -> str:
    """Execute a shell command and return the output.

    This is a general-purpose escape hatch for running any command available
    in the Kali container. Use structured tools when available; fall back to
    this for custom pipelines or tools without a dedicated wrapper.

    Args:
        command: Shell command to execute
        timeout: Timeout in seconds (default 300)
        workdir: Working directory (default /opt/workspace)
    """
    result = await run_shell(command, timeout=timeout, workdir=workdir)
    return json.dumps({
        "stdout": result.stdout,
        "stderr": result.stderr,
        "exit_code": result.exit_code,
        "timed_out": result.timed_out,
    }, indent=2)


@mcp.tool()
async def background_command(
    command: str,
    timeout: int = 3600,
) -> str:
    """Start a long-running command in the background.

    Returns a job_id that can be checked with check_job or cancelled with cancel_job.
    Useful for scans that take a long time (large nmap, amass, etc.).

    The process is automatically killed after the timeout expires.

    Args:
        command: Shell command to run in background
        timeout: Maximum runtime in seconds (default 3600 = 1 hour)
    """
    job_id = str(uuid.uuid4())[:8]
    output_file = f"{JOBS_DIR}/{job_id}.out"

    # Launch command in a subshell that self-terminates after timeout
    bg_command = (
        f"mkdir -p {JOBS_DIR} && "
        f"( timeout {timeout} sh -c {_shell_quote(command)} ) > {output_file} 2>&1 & echo $!"
    )

    result = await run_shell(bg_command, timeout=5)
    pid = result.stdout.strip()

    _background_jobs[job_id] = {
        "pid": pid,
        "command": command,
        "output_file": output_file,
        "timeout": timeout,
    }

    return json.dumps({
        "job_id": job_id,
        "pid": pid,
        "output_file": output_file,
        "message": f"Job started. Use check_job('{job_id}') to monitor progress.",
    }, indent=2)


@mcp.tool()
async def check_job(
    job_id: str,
    tail_lines: int = 50,
) -> str:
    """Check the status and output of a background job.

    Args:
        job_id: The job_id returned by background_command
        tail_lines: Number of output lines to return from the end (default 50)
    """
    output_file = f"{JOBS_DIR}/{job_id}.out"
    job = _background_jobs.get(job_id, {})
    pid_str = job.get("pid", "")

    running = False
    if pid_str and pid_str.isdigit():
        running = _pid_alive(int(pid_str))

    output = ""
    if os.path.exists(output_file):
        try:
            with open(output_file) as f:
                lines = f.readlines()
                output = "".join(lines[-tail_lines:])
        except OSError:
            output = "[error reading output file]"
    else:
        output = "[no output file yet]"

    return json.dumps({
        "job_id": job_id,
        "status": "running" if running else "completed",
        "pid": pid_str,
        "command": job.get("command", "unknown"),
        "output_tail": output,
    }, indent=2)


@mcp.tool()
async def cancel_job(job_id: str) -> str:
    """Cancel a running background job.

    Args:
        job_id: The job_id returned by background_command
    """
    job = _background_jobs.get(job_id, {})
    pid_str = job.get("pid", "")

    if not pid_str or not pid_str.isdigit():
        return json.dumps({"error": f"Unknown job: {job_id}"}, indent=2)

    pid = int(pid_str)
    if not _pid_alive(pid):
        return json.dumps({
            "job_id": job_id,
            "status": "already_completed",
            "message": "Process is no longer running.",
        }, indent=2)

    try:
        os.kill(pid, signal.SIGTERM)
        return json.dumps({
            "job_id": job_id,
            "status": "cancelled",
            "message": f"Sent SIGTERM to PID {pid}.",
        }, indent=2)
    except OSError as e:
        return json.dumps({
            "job_id": job_id,
            "status": "error",
            "message": f"Failed to kill PID {pid}: {e}",
        }, indent=2)


def _shell_quote(s: str) -> str:
    """Single-quote a string for safe embedding in sh -c."""
    return "'" + s.replace("'", "'\\''") + "'"
