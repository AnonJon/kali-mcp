FROM kalilinux/kali-rolling

LABEL maintainer="kali-mcp"
LABEL description="Kali Linux MCP server - 30 offensive security tools over stdio JSON-RPC"

ENV DEBIAN_FRONTEND=noninteractive

# ── 1. System packages ───────────────────────────────────────────────────────
RUN set -eux; \
    if [ -f /etc/apt/sources.list.d/kali.sources ]; then \
        sed -i 's|http://http.kali.org/kali/|http://kali.download/kali/|g' /etc/apt/sources.list.d/kali.sources; \
    fi; \
    printf '%s\n' \
        'Acquire::Retries "5";' \
        'Acquire::http::Timeout "60";' \
        'Acquire::https::Timeout "60";' \
        > /etc/apt/apt.conf.d/80-retries; \
    packages=" \
        nmap masscan whois dnsutils \
        nikto sqlmap hydra exploitdb \
        testssl.sh sslscan \
        gobuster ffuf whatweb wafw00f wpscan \
        commix john ncat hping3 dirb seclists \
        curl wget jq \
        python3 python3-pip \
        golang-go git unzip \
        wordlists \
    "; \
    for attempt in 1 2 3; do \
        apt-get clean; \
        rm -rf /var/lib/apt/lists/*; \
        apt-get update -qq --allow-releaseinfo-change; \
        if apt-get install -y -qq --fix-missing --no-install-recommends $packages; then \
            break; \
        fi; \
        if [ "$attempt" = "3" ]; then \
            echo "apt install failed after 3 attempts" >&2; \
            exit 1; \
        fi; \
        sleep $((attempt * 15)); \
    done; \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# ── 2. ProjectDiscovery tools (nuclei, httpx, subfinder, dnsx) ───────────────
RUN export GOPATH=/root/go && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    mv /root/go/bin/* /usr/local/bin/ && \
    rm -rf /root/go && \
    nuclei -update-templates 2>/dev/null || true

# ── 3. Dalfox (XSS scanner, Go-based) ───────────────────────────────────────
RUN export GOPATH=/root/go && \
    go install github.com/hahwul/dalfox/v2@latest && \
    mv /root/go/bin/dalfox /usr/local/bin/ && \
    rm -rf /root/go

# ── 4. Amass ─────────────────────────────────────────────────────────────────
RUN AMASS_URL=$(curl -s "https://api.github.com/repos/owasp-amass/amass/releases/latest" \
        | jq -r '.assets[] | select(.name | test("linux.*amd64\\.zip$")) | .browser_download_url' \
        | head -1) && \
    if [ -n "$AMASS_URL" ]; then \
        curl -sSL "$AMASS_URL" -o /tmp/amass.zip && \
        unzip -o /tmp/amass.zip -d /tmp/ 2>/dev/null || true && \
        find /tmp -name amass -type f -executable -exec mv {} /usr/local/bin/ \; && \
        chmod +x /usr/local/bin/amass 2>/dev/null || true; \
    fi && \
    rm -f /tmp/amass.zip

# ── 5. Workspace and wordlists ───────────────────────────────────────────────
RUN mkdir -p /opt/workspace/jobs && \
    if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then \
        gunzip /usr/share/wordlists/rockyou.txt.gz; \
    fi

# ── 6. Install kali-mcp Python package ──────────────────────────────────────
COPY . /opt/kali-mcp
RUN pip3 install --break-system-packages /opt/kali-mcp

# MCP stdio server entrypoint
ENTRYPOINT ["python3", "-m", "kali_mcp"]
