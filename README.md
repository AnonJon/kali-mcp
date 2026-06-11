# kali-mcp

A Kali Linux MCP server that exposes 30 offensive security tools as structured, typed MCP tools over stdio JSON-RPC. Designed to run as a single Docker container compatible with [Orloj](https://github.com/OrlojHQ/orloj) and any MCP-compatible client.

## Tools (30)

| Category              | Tools                                                                                                     |
| --------------------- | --------------------------------------------------------------------------------------------------------- |
| Reconnaissance (7)    | nmap_scan, masscan_scan, whois_lookup, dig_lookup, subfinder_scan, amass_enum, dnsx_resolve               |
| Web Scanning (8)      | nikto_scan, nuclei_scan, gobuster_scan, ffuf_fuzz, httpx_probe, whatweb_scan, wafw00f_detect, wpscan_scan |
| TLS/SSL (2)           | testssl_check, sslscan_target                                                                             |
| Exploitation (5)      | sqlmap_scan, hydra_attack, searchsploit_search, dalfox_scan, commix_scan                                  |
| Password Cracking (1) | john_crack                                                                                                |
| Networking (3)        | curl_request, ncat_connect, hping3_probe                                                                  |
| Shell (4)             | execute_command, background_command, check_job, cancel_job                                                |

All tools accept structured typed inputs and return parsed JSON output.

## Quick Start

### Build the Docker image

```bash
docker build -t kali-mcp:latest .
```

### Run standalone (stdio)

```bash
docker run --rm -i kali-mcp:latest
```

Some tools (nmap SYN/OS scans, masscan, hping3) require raw socket access. Add `--cap-add=NET_RAW` or run with `--privileged`:

```bash
docker run --rm -i --cap-add=NET_RAW kali-mcp:latest
```

### Use with Orloj

```yaml
apiVersion: orloj.dev/v1
kind: McpServer
metadata:
  name: kali-mcp
spec:
  transport: stdio
  image: "kali-mcp:latest"
  resources:
    memory: "4g"
    cpus: "2.0"
```

### Use with Claude Desktop / MCP clients

```json
{
  "mcpServers": {
    "kali-mcp": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "--cap-add=NET_RAW", "kali-mcp:latest"]
    }
  }
}
```

## Development

```bash
pip install -e .
python -m kali_mcp
```

## Architecture

- **FastMCP** framework for MCP protocol handling
- **Async subprocess execution** with timeout, ANSI stripping, and input sanitization
- **Structured output** - tools use native JSON/XML output modes where available (nmap `-oX`, nuclei `-jsonl`, searchsploit `--json`, etc.)
- **Single process** - entrypoint immediately speaks MCP JSON-RPC on stdin/stdout

## Security

This server provides direct access to offensive security tools. Only use against systems you have explicit written authorization to test.
