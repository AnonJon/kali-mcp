"""TLS/SSL analysis tools: testssl, sslscan."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET

from kali_mcp.executor import build_command, run_command, sanitize_input
from kali_mcp.server import mcp


@mcp.tool()
async def testssl_check(target: str) -> str:
    """Run comprehensive TLS/SSL analysis using testssl.sh.

    Checks protocols, ciphers, vulnerabilities (Heartbleed, POODLE, etc.), and certificate details.

    Args:
        target: Target host:port (e.g. "example.com:443" or "example.com")
    """
    target = sanitize_input(target)
    args = ["--jsonfile", "-", "--quiet", "--color", "0", target]

    result = await run_command(build_command("testssl", args), timeout=300)
    if result.exit_code != 0 and not result.stdout:
        result2 = await run_command(build_command("testssl.sh", args), timeout=300)
        if result2.stdout:
            result = result2

    if not result.stdout:
        return result.to_json()

    try:
        data = json.loads(result.stdout)
        return json.dumps(data, indent=2)
    except json.JSONDecodeError:
        return json.dumps({"raw_output": result.stdout[:5000]}, indent=2)


@mcp.tool()
async def sslscan_target(target: str) -> str:
    """Scan TLS/SSL configuration using sslscan.

    Args:
        target: Target host:port (e.g. "example.com:443" or "example.com")
    """
    target = sanitize_input(target)
    args = ["--no-colour", "--xml=-", target]

    result = await run_command(build_command("sslscan", args), timeout=60)
    if result.exit_code != 0 and not result.stdout:
        return result.to_json()

    try:
        return json.dumps(_parse_sslscan_xml(result.stdout), indent=2)
    except Exception:
        return json.dumps({"raw_output": result.stdout[:5000]}, indent=2)


def _parse_sslscan_xml(xml_str: str) -> dict:
    """Parse sslscan XML output into structured JSON."""
    root = ET.fromstring(xml_str)
    data: dict = {"protocols": [], "ciphers": [], "certificate": {}}

    for test in root.findall(".//ssltest"):
        target = test.get("host", "")
        data["target"] = f"{target}:{test.get('port', '443')}"

    for proto in root.findall(".//protocol"):
        data["protocols"].append({
            "type": proto.get("type", ""),
            "version": proto.get("version", ""),
            "enabled": proto.get("enabled", "") == "1",
        })

    for cipher in root.findall(".//cipher"):
        data["ciphers"].append({
            "status": cipher.get("status", ""),
            "ssl_version": cipher.get("sslversion", ""),
            "bits": cipher.get("bits", ""),
            "cipher": cipher.get("cipher", ""),
        })

    cert = root.find(".//certificate")
    if cert is not None:
        subject = cert.find("subject")
        issuer = cert.find("issuer")
        data["certificate"] = {
            "subject": subject.text if subject is not None else "",
            "issuer": issuer.text if issuer is not None else "",
        }
        not_before = cert.find("not-valid-before")
        not_after = cert.find("not-valid-after")
        if not_before is not None:
            data["certificate"]["not_before"] = not_before.text
        if not_after is not None:
            data["certificate"]["not_after"] = not_after.text

    return data
