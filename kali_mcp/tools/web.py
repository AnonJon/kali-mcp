"""Web scanning tools: nikto, nuclei, gobuster, ffuf, httpx, whatweb, wafw00f, wpscan."""

from __future__ import annotations

import json

from kali_mcp.executor import build_command, run_command, sanitize_input
from kali_mcp.server import mcp


@mcp.tool()
async def nikto_scan(
    target: str,
    port: int = 0,
    tuning: str = "",
) -> str:
    """Run Nikto web server scanner.

    Args:
        target: Target URL or host (e.g. "http://example.com" or "192.168.1.1")
        port: Specific port to scan (0 = auto-detect from URL)
        tuning: Nikto tuning options (e.g. "123" for interesting files, misconfigs, info disclosure)
    """
    target = sanitize_input(target)
    args = ["-h", target, "-Format", "json", "-output", "-"]
    if port > 0:
        args += ["-p", str(port)]
    if tuning:
        args += ["-Tuning", sanitize_input(tuning)]

    result = await run_command(build_command("nikto", args), timeout=300)
    if result.exit_code != 0 and not result.stdout:
        return result.to_json()

    try:
        data = json.loads(result.stdout)
        return json.dumps(data, indent=2)
    except json.JSONDecodeError:
        return json.dumps({"raw_output": result.stdout, "exit_code": result.exit_code}, indent=2)


@mcp.tool()
async def nuclei_scan(
    target: str,
    severity: str = "critical,high",
    templates: str = "",
    tags: str = "",
) -> str:
    """Run Nuclei vulnerability scanner with template-based detection.

    Args:
        target: Target URL to scan
        severity: Comma-separated severity filter (critical, high, medium, low, info)
        templates: Specific template IDs or paths (comma-separated)
        tags: Template tags to filter by (e.g. "cve,rce,sqli")
    """
    target = sanitize_input(target)
    args = ["-target", target, "-jsonl", "-silent", "-no-color", "-duc"]
    if severity:
        args += ["-severity", sanitize_input(severity)]
    if templates:
        args += ["-templates", sanitize_input(templates)]
    if tags:
        args += ["-tags", sanitize_input(tags)]

    result = await run_command(build_command("nuclei", args), timeout=600)
    if result.exit_code != 0 and not result.stdout:
        return result.to_json()

    findings = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    return json.dumps({"target": target, "findings": findings, "count": len(findings)}, indent=2)


@mcp.tool()
async def gobuster_scan(
    target: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    extensions: str = "",
    mode: str = "dir",
    threads: int = 10,
) -> str:
    """Run Gobuster for directory/DNS/vhost enumeration.

    Args:
        target: Target URL (dir mode) or domain (dns mode)
        wordlist: Path to wordlist file (default: dirb/common.txt)
        extensions: File extensions to check (e.g. "php,html,js,txt")
        mode: Scan mode: dir, dns, vhost
        threads: Number of concurrent threads (default 10)
    """
    target = sanitize_input(target)
    mode = sanitize_input(mode)
    args = [mode, "-u" if mode != "dns" else "-d", target, "-w", wordlist, "-t", str(threads), "-q", "--no-color"]
    if extensions and mode == "dir":
        args += ["-x", sanitize_input(extensions)]

    result = await run_command(build_command("gobuster", args), timeout=300)
    if result.exit_code != 0 and not result.stdout:
        return result.to_json()

    entries = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 1:
            entry: dict = {"path": parts[0]}
            if len(parts) >= 2:
                entry["status"] = parts[1].strip("()")
            if len(parts) >= 3:
                entry["size"] = parts[2]
            entries.append(entry)

    return json.dumps({"target": target, "mode": mode, "results": entries, "count": len(entries)}, indent=2)


@mcp.tool()
async def ffuf_fuzz(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    method: str = "GET",
    match_codes: str = "200,204,301,302,307,401,403",
    filters: str = "",
) -> str:
    """Run ffuf web fuzzer. Use FUZZ keyword in the URL for substitution point.

    Args:
        url: Target URL with FUZZ keyword (e.g. "http://target.com/FUZZ")
        wordlist: Path to wordlist file
        method: HTTP method (GET, POST, etc.)
        match_codes: Status codes to match (comma-separated)
        filters: Filter responses by size/words/lines (e.g. "fs=0" or "fw=42")
    """
    url = sanitize_input(url)
    args = [
        "-u", url,
        "-w", wordlist,
        "-X", sanitize_input(method).upper(),
        "-mc", sanitize_input(match_codes),
        "-json",
        "-silent",
    ]
    if filters:
        for f in filters.split(","):
            f = sanitize_input(f.strip())
            if f.startswith("fs="):
                args += ["-fs", f[3:]]
            elif f.startswith("fw="):
                args += ["-fw", f[3:]]
            elif f.startswith("fl="):
                args += ["-fl", f[3:]]

    result = await run_command(build_command("ffuf", args), timeout=300)
    if result.exit_code != 0 and not result.stdout:
        return result.to_json()

    try:
        data = json.loads(result.stdout)
        return json.dumps(data, indent=2)
    except json.JSONDecodeError:
        return json.dumps({"raw_output": result.stdout}, indent=2)


@mcp.tool()
async def httpx_probe(
    targets: list[str],
    ports: str = "",
    paths: str = "",
) -> str:
    """Probe targets for live HTTP services using httpx.

    Args:
        targets: List of hosts/URLs to probe
        ports: Ports to check (e.g. "80,443,8080")
        paths: Paths to append (e.g. "/admin,/api")
    """
    stdin_data = "\n".join(sanitize_input(t) for t in targets)
    args = ["-json", "-silent", "-no-color", "-title", "-tech-detect", "-status-code"]
    if ports:
        args += ["-ports", sanitize_input(ports)]
    if paths:
        args += ["-path", sanitize_input(paths)]

    result = await run_command(
        build_command("httpx", args),
        stdin_data=stdin_data,
        timeout=120,
    )
    if result.exit_code != 0 and not result.stdout:
        return result.to_json()

    results = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    return json.dumps({"live_hosts": results, "count": len(results)}, indent=2)


@mcp.tool()
async def whatweb_scan(target: str) -> str:
    """Identify web technologies using WhatWeb.

    Args:
        target: Target URL to fingerprint
    """
    target = sanitize_input(target)
    args = ["--log-json=-", "-q", target]

    result = await run_command(build_command("whatweb", args), timeout=60)
    if result.exit_code != 0 and not result.stdout:
        return result.to_json()

    try:
        data = json.loads(result.stdout)
        return json.dumps(data, indent=2)
    except json.JSONDecodeError:
        return json.dumps({"raw_output": result.stdout}, indent=2)


@mcp.tool()
async def wafw00f_detect(target: str) -> str:
    """Detect Web Application Firewalls using wafw00f.

    Args:
        target: Target URL to check for WAF
    """
    target = sanitize_input(target)
    args = [target, "-o", "-", "-f", "json"]

    result = await run_command(build_command("wafw00f", args), timeout=30)
    if result.exit_code != 0 and not result.stdout:
        return result.to_json()

    try:
        data = json.loads(result.stdout)
        return json.dumps(data, indent=2)
    except json.JSONDecodeError:
        lines = result.stdout.splitlines()
        detected = [l for l in lines if "detected" in l.lower() or "behind" in l.lower()]
        return json.dumps({"target": target, "detection": detected or ["No WAF detected"]}, indent=2)


@mcp.tool()
async def wpscan_scan(
    target: str,
    enumerate: str = "vp,vt,u",
    api_token: str = "",
) -> str:
    """Scan WordPress sites for vulnerabilities using WPScan.

    Args:
        target: WordPress site URL
        enumerate: What to enumerate: vp (vulnerable plugins), vt (vulnerable themes), u (users), ap (all plugins)
        api_token: WPScan API token for vulnerability data (optional)
    """
    target = sanitize_input(target)
    args = ["--url", target, "--format", "json", "--no-banner"]
    if enumerate:
        args += ["--enumerate", sanitize_input(enumerate)]
    if api_token:
        args += ["--api-token", sanitize_input(api_token)]

    result = await run_command(build_command("wpscan", args), timeout=300)
    if result.exit_code != 0 and not result.stdout:
        return result.to_json()

    try:
        data = json.loads(result.stdout)
        return json.dumps(data, indent=2)
    except json.JSONDecodeError:
        return json.dumps({"raw_output": result.stdout}, indent=2)
