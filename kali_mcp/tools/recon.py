"""Reconnaissance tools: nmap, masscan, whois, dig, subfinder, amass, dnsx."""

from __future__ import annotations

import json
import shutil
import tempfile
import xml.etree.ElementTree as ET

from kali_mcp.executor import build_command, run_command, sanitize_input
from kali_mcp.server import mcp


@mcp.tool()
async def nmap_scan(
    target: str,
    ports: str = "",
    scan_type: str = "service",
    scripts: str = "",
    timing_template: int = 3,
) -> str:
    """Run an Nmap scan against a target with structured output.

    Args:
        target: IP address, hostname, or CIDR range to scan
        ports: Port specification (e.g. "80,443", "1-1000", "-" for all). Empty = default top ports
        scan_type: One of: quick (top 100), service (-sV), full (-p- -sV -sC), vuln (--script vuln), udp (-sU)
        scripts: Comma-separated NSE scripts to run (e.g. "http-enum,ssl-cert")
        timing_template: Timing template 0-5 (default 3, higher = faster/noisier)
    """
    target = sanitize_input(target)
    args = ["-oX", "-"]

    if scan_type == "quick":
        args += ["-F", "-sV"]
    elif scan_type == "service":
        args += ["-sV", "--version-intensity", "5"]
    elif scan_type == "full":
        args += ["-p-", "-sV", "-sC", "-O"]
    elif scan_type == "vuln":
        args += ["-sV", "--script", "vuln"]
    elif scan_type == "udp":
        args += ["-sU", "-sV"]
    else:
        args += ["-sV"]

    if ports:
        args += ["-p", sanitize_input(ports)]
    if scripts:
        args += ["--script", sanitize_input(scripts)]

    args += [f"-T{max(0, min(5, timing_template))}"]
    args.append(target)

    result = await run_command(build_command("nmap", args), timeout=600)
    if result.exit_code != 0 and not result.stdout:
        return result.to_json()

    try:
        return json.dumps(_parse_nmap_xml(result.stdout), indent=2)
    except Exception:
        return result.to_json()


def _parse_nmap_xml(xml_str: str) -> dict:
    """Parse nmap XML output into structured JSON."""
    root = ET.fromstring(xml_str)
    hosts = []
    for host_el in root.findall("host"):
        addr_el = host_el.find("address")
        host_data: dict = {
            "address": addr_el.get("addr", "") if addr_el is not None else "",
            "state": "unknown",
            "ports": [],
        }
        status_el = host_el.find("status")
        if status_el is not None:
            host_data["state"] = status_el.get("state", "unknown")

        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            names = [h.get("name", "") for h in hostnames_el.findall("hostname")]
            if names:
                host_data["hostnames"] = names

        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                port_data: dict = {
                    "port": int(port_el.get("portid", 0)),
                    "protocol": port_el.get("protocol", "tcp"),
                }
                state_el = port_el.find("state")
                if state_el is not None:
                    port_data["state"] = state_el.get("state", "")
                service_el = port_el.find("service")
                if service_el is not None:
                    port_data["service"] = service_el.get("name", "")
                    if service_el.get("product"):
                        port_data["product"] = service_el.get("product", "")
                    if service_el.get("version"):
                        port_data["version"] = service_el.get("version", "")
                scripts_out = []
                for script_el in port_el.findall("script"):
                    scripts_out.append({
                        "id": script_el.get("id", ""),
                        "output": script_el.get("output", ""),
                    })
                if scripts_out:
                    port_data["scripts"] = scripts_out
                host_data["ports"].append(port_data)
        hosts.append(host_data)

    return {"hosts": hosts, "scan_info": root.get("args", "")}


@mcp.tool()
async def masscan_scan(
    target: str,
    ports: str = "1-65535",
    rate: int = 1000,
) -> str:
    """Run a Masscan port scan (fast, async SYN scanner).

    Args:
        target: IP address or CIDR range to scan
        ports: Port range (e.g. "80,443" or "1-65535")
        rate: Packets per second (default 1000)
    """
    target = sanitize_input(target)
    ports = sanitize_input(ports)
    args = [
        "-p", ports,
        "--rate", str(max(1, min(100000, rate))),
        "--open",
        "--wait", "0",
        "-oJ", "-",
        target,
    ]
    result = await run_command(build_command("masscan", args), timeout=300)
    if result.exit_code != 0 and not result.stdout:
        return result.to_json()

    try:
        lines = [l for l in result.stdout.strip().splitlines() if l.strip().startswith("{")]
        entries = [json.loads(l.rstrip(",")) for l in lines]
        return json.dumps({"open_ports": entries}, indent=2)
    except Exception:
        return result.to_json()


@mcp.tool()
async def whois_lookup(domain: str) -> str:
    """Perform a WHOIS lookup on a domain or IP address.

    Args:
        domain: Domain name or IP address to query
    """
    domain = sanitize_input(domain)
    result = await run_command(build_command("whois", [domain]), timeout=30)
    if result.exit_code != 0:
        return result.to_json()

    data: dict = {"raw": result.stdout}
    lines = result.stdout.splitlines()
    for line in lines:
        lower = line.lower()
        if "registrar:" in lower:
            data["registrar"] = line.split(":", 1)[1].strip()
        elif "creation date:" in lower or "created:" in lower:
            data["created"] = line.split(":", 1)[1].strip()
        elif "expir" in lower and "date:" in lower:
            data["expires"] = line.split(":", 1)[1].strip()
        elif "name server:" in lower or "nserver:" in lower:
            ns = line.split(":", 1)[1].strip()
            data.setdefault("nameservers", []).append(ns)
        elif "registrant" in lower and "org" in lower and ":" in line:
            data["registrant_org"] = line.split(":", 1)[1].strip()

    return json.dumps(data, indent=2)


@mcp.tool()
async def dig_lookup(
    domain: str,
    record_type: str = "A",
    nameserver: str = "",
) -> str:
    """Perform DNS lookups using dig.

    Args:
        domain: Domain name to query
        record_type: DNS record type: A, AAAA, MX, NS, TXT, CNAME, SOA, ANY
        nameserver: Optional DNS server to query (e.g. "8.8.8.8")
    """
    domain = sanitize_input(domain)
    record_type = sanitize_input(record_type).upper()
    args = ["+noall", "+answer", "+authority", domain, record_type]
    if nameserver:
        args = [f"@{sanitize_input(nameserver)}"] + args

    result = await run_command(build_command("dig", args), timeout=30)
    if result.exit_code != 0:
        return result.to_json()

    records = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        parts = line.split(None, 4)
        if len(parts) >= 5:
            records.append({
                "name": parts[0],
                "ttl": int(parts[1]) if parts[1].isdigit() else 0,
                "class": parts[2],
                "type": parts[3],
                "value": parts[4],
            })

    return json.dumps({"domain": domain, "type": record_type, "records": records}, indent=2)


@mcp.tool()
async def subfinder_scan(domain: str) -> str:
    """Enumerate subdomains using subfinder.

    Args:
        domain: Target domain to enumerate subdomains for
    """
    domain = sanitize_input(domain)
    args = ["-d", domain, "-json", "-silent"]
    result = await run_command(build_command("subfinder", args), timeout=120)
    if result.exit_code != 0 and not result.stdout:
        return result.to_json()

    subdomains = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            subdomains.append(entry.get("host", line))
        except json.JSONDecodeError:
            subdomains.append(line)

    return json.dumps({"domain": domain, "subdomains": sorted(set(subdomains))}, indent=2)


@mcp.tool()
async def amass_enum(
    domain: str,
    active: bool = False,
    timeout_minutes: int = 5,
) -> str:
    """Enumerate subdomains using OWASP Amass.

    Amass v5 runs the enumeration into a local graph database (passive by
    default) and the discovered names are then read back out, so this runs
    `amass enum` followed by `amass subs -names` against a shared directory.

    Args:
        domain: Target domain to enumerate
        active: If True, enable active techniques (zone transfers, cert grabbing). Default passive.
        timeout_minutes: Max minutes amass runs without progress before stopping (1-60, default 5)
    """
    domain = sanitize_input(domain)
    timeout_minutes = max(1, min(60, timeout_minutes))
    workdir = tempfile.mkdtemp(prefix="amass_")
    try:
        enum_args = [
            "enum",
            "-d", domain,
            "-dir", workdir,
            "-timeout", str(timeout_minutes),
            "-silent",
        ]
        if active:
            enum_args.append("-active")

        enum_result = await run_command(
            build_command("amass", enum_args),
            timeout=timeout_minutes * 60 + 120,
        )

        subs_result = await run_command(
            build_command("amass", ["subs", "-d", domain, "-dir", workdir, "-names", "-nocolor"]),
            timeout=60,
        )

        subdomains = sorted({
            line.strip()
            for line in subs_result.stdout.splitlines()
            if line.strip() and "." in line and " " not in line.strip()
        })

        if not subdomains and enum_result.exit_code != 0 and subs_result.exit_code != 0:
            return json.dumps({
                "domain": domain,
                "error": "amass enumeration failed",
                "enum_stderr": enum_result.stderr[-1000:],
                "subs_stderr": subs_result.stderr[-1000:],
            }, indent=2)

        return json.dumps({"domain": domain, "subdomains": subdomains, "count": len(subdomains)}, indent=2)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


@mcp.tool()
async def dnsx_resolve(
    domains: list[str],
    record_type: str = "A",
) -> str:
    """Resolve multiple domains using dnsx with structured output.

    Args:
        domains: List of domains/subdomains to resolve
        record_type: DNS record type to query (A, AAAA, CNAME, MX, NS, TXT)
    """
    record_type = sanitize_input(record_type).upper()
    cleaned_domains = [sanitize_input(d) for d in domains if d and d.strip()]
    if not cleaned_domains:
        return json.dumps({"record_type": record_type, "results": []}, indent=2)
    stdin_data = "\n".join(cleaned_domains)
    type_flag = f"-{record_type.lower()}"
    args = [type_flag, "-resp", "-json", "-silent"]

    result = await run_command(
        build_command("dnsx", args),
        stdin_data=stdin_data,
        timeout=60,
    )
    if result.exit_code != 0 and not result.stdout:
        return result.to_json()

    records = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    return json.dumps({"record_type": record_type, "results": records}, indent=2)
