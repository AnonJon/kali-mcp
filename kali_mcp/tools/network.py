"""Networking tools: curl, ncat, hping3."""

from __future__ import annotations

import json

from kali_mcp.executor import build_command, run_command, sanitize_input
from kali_mcp.server import mcp


@mcp.tool()
async def curl_request(
    url: str,
    method: str = "GET",
    headers: list[str] | None = None,
    data: str = "",
    follow_redirects: bool = True,
    timeout: int = 30,
) -> str:
    """Make HTTP requests using curl with full control.

    Args:
        url: Target URL
        method: HTTP method (GET, POST, PUT, DELETE, etc.)
        headers: List of headers (e.g. ["Authorization: Bearer token", "Content-Type: application/json"])
        data: Request body data
        follow_redirects: Follow HTTP redirects (default True)
        timeout: Request timeout in seconds
    """
    url = sanitize_input(url)
    args = [
        "-s",
        "-w", "\n---CURL_STATUS:%{http_code}---\n",
        "-X", sanitize_input(method).upper(),
        "--max-time", str(timeout),
        "-D", "-",
    ]
    if follow_redirects:
        args.append("-L")
    if headers:
        for h in headers:
            args += ["-H", sanitize_input(h)]
    if data:
        args += ["-d", data]
    args.append(url)

    result = await run_command(build_command("curl", args), timeout=timeout + 10)
    if result.exit_code != 0 and not result.stdout:
        return result.to_json()

    output = result.stdout
    status_code = 0
    if "---CURL_STATUS:" in output:
        parts = output.rsplit("---CURL_STATUS:", 1)
        try:
            status_code = int(parts[1].split("---")[0])
        except (ValueError, IndexError):
            pass
        output = parts[0]

    header_blocks: list[str] = []
    body = output
    while body.lstrip().startswith("HTTP/"):
        if "\r\n\r\n" in body:
            hdr, body = body.split("\r\n\r\n", 1)
            header_blocks.append(hdr)
        elif "\n\n" in body:
            hdr, body = body.split("\n\n", 1)
            header_blocks.append(hdr)
        else:
            break
    resp_headers = "\n\n".join(header_blocks)

    truncated = len(body) > 2000
    return json.dumps({
        "status_code": status_code,
        "headers": resp_headers[:2000],
        "body": body[:2000],
        "body_length": len(body),
        "truncated": truncated,
    }, indent=2)


@mcp.tool()
async def ncat_connect(
    target: str,
    port: int,
    data: str = "",
    timeout: int = 10,
) -> str:
    """Connect to a TCP/UDP service using Ncat and send/receive data.

    Args:
        target: Target host
        port: Target port
        data: Data to send (optional)
        timeout: Connection timeout in seconds
    """
    target = sanitize_input(target)
    args = [target, str(port), "-w", str(timeout)]

    result = await run_command(
        build_command("ncat", args),
        stdin_data=data if data else None,
        timeout=timeout + 5,
    )

    return json.dumps({
        "target": f"{target}:{port}",
        "response": result.stdout,
        "exit_code": result.exit_code,
    }, indent=2)


@mcp.tool()
async def hping3_probe(
    target: str,
    port: int = 80,
    flags: str = "S",
    count: int = 3,
) -> str:
    """Send crafted TCP/IP packets using hping3 for advanced probing.

    Args:
        target: Target host
        port: Target port (default 80)
        flags: TCP flags: S(YN), A(CK), F(IN), R(ST), P(USH), U(RG)
        count: Number of packets to send (default 3)
    """
    target = sanitize_input(target)
    flags = sanitize_input(flags)
    args = [target, "-p", str(port), "-c", str(min(count, 100))]

    flag_map = {"S": "-S", "A": "-A", "F": "-F", "R": "-R", "P": "-P", "U": "-U"}
    for f in flags.upper():
        if f in flag_map:
            args.append(flag_map[f])

    result = await run_command(build_command("hping3", args), timeout=30)
    combined_output = "\n".join(part for part in (result.stdout, result.stderr) if part)

    return json.dumps({
        "target": f"{target}:{port}",
        "flags": flags,
        "count": count,
        "output": combined_output,
        "exit_code": result.exit_code,
    }, indent=2)
