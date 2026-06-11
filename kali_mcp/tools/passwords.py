"""Password cracking tools: john."""

from __future__ import annotations

import json
import os

from kali_mcp.executor import build_command, run_command, write_temp_file
from kali_mcp.server import mcp


@mcp.tool()
async def john_crack(
    hash_file_content: str,
    format: str = "",
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
    rules: str = "",
) -> str:
    """Crack password hashes using John the Ripper.

    Args:
        hash_file_content: Hash file content (one hash per line, e.g. "user:$6$salt$hash")
        format: Hash format (e.g. "raw-md5", "sha512crypt", "bcrypt"). Empty = auto-detect.
        wordlist: Path to wordlist (default: rockyou.txt)
        rules: John rules to apply (e.g. "best64", "dive")
    """
    hash_file = write_temp_file(hash_file_content, suffix=".hashes")

    try:
        args = [hash_file, "--wordlist=" + wordlist]
        if format:
            args.append(f"--format={format}")
        if rules:
            args.append(f"--rules={rules}")

        result = await run_command(build_command("john", args), timeout=600)

        show_result = await run_command(
            build_command("john", ["--show", hash_file] + ([f"--format={format}"] if format else [])),
            timeout=10,
        )

        cracked = []
        for line in show_result.stdout.splitlines():
            if ":" in line and not line.startswith("0 password") and "password hashes cracked" not in line:
                cracked.append(line.strip())

        return json.dumps({
            "cracked": cracked,
            "count": len(cracked),
            "run_output": result.stdout[-2000:] if len(result.stdout) > 2000 else result.stdout,
        }, indent=2)
    finally:
        os.unlink(hash_file)
