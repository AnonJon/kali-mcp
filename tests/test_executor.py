"""Tests for kali_mcp.executor."""

from __future__ import annotations

import asyncio
import json
import os

import pytest

from kali_mcp.executor import (
    ExecResult,
    _truncate,
    build_command,
    run_command,
    run_shell,
    sanitize_input,
    strip_ansi,
    write_temp_file,
)


class TestStripAnsi:
    def test_removes_color_codes(self):
        assert strip_ansi("\x1b[31mred\x1b[0m") == "red"

    def test_removes_cursor_movement(self):
        assert strip_ansi("\x1b[2Jhello") == "hello"

    def test_removes_carriage_return(self):
        assert strip_ansi("line1\rline2") == "line1line2"

    def test_plain_text_unchanged(self):
        assert strip_ansi("hello world") == "hello world"

    def test_removes_osc_sequences(self):
        assert strip_ansi("\x1b]0;title\x07text") == "text"

    def test_empty_string(self):
        assert strip_ansi("") == ""


class TestSanitizeInput:
    def test_strips_whitespace(self):
        assert sanitize_input("  hello  ") == "hello"

    def test_allows_normal_input(self):
        assert sanitize_input("192.168.1.1") == "192.168.1.1"
        assert sanitize_input("example.com") == "example.com"
        assert sanitize_input("80,443,8080") == "80,443,8080"

    def test_allows_ampersand_in_urls_and_forms(self):
        assert sanitize_input("http://example.com/page?id=1&cat=2") == "http://example.com/page?id=1&cat=2"
        form = "/login:user=^USER^&pass=^PASS^:F=incorrect"
        assert sanitize_input(form) == form

    def test_blocks_double_ampersand(self):
        with pytest.raises(ValueError):
            sanitize_input("target && rm -rf /")

    def test_blocks_semicolon(self):
        with pytest.raises(ValueError):
            sanitize_input("target; rm -rf /")

    def test_blocks_pipe(self):
        with pytest.raises(ValueError):
            sanitize_input("target | cat /etc/passwd")

    def test_blocks_backtick(self):
        with pytest.raises(ValueError):
            sanitize_input("target `whoami`")

    def test_blocks_dollar(self):
        with pytest.raises(ValueError):
            sanitize_input("target $HOME")

    def test_blocks_command_substitution(self):
        with pytest.raises(ValueError):
            sanitize_input("target $(id)")

    def test_blocks_redirect_to_root(self):
        with pytest.raises(ValueError):
            sanitize_input("> /etc/passwd")

    def test_allows_shell_chars_when_flag_set(self):
        result = sanitize_input("echo hello; ls", allow_shell_chars=True)
        assert result == "echo hello; ls"


class TestBuildCommand:
    def test_basic_command(self):
        assert build_command("nmap", ["-sV", "target"]) == ["nmap", "-sV", "target"]

    def test_filters_empty_strings(self):
        assert build_command("nmap", ["-sV", "", "target", ""]) == ["nmap", "-sV", "target"]

    def test_no_args(self):
        assert build_command("whoami", []) == ["whoami"]


class TestTruncate:
    def test_short_text_unchanged(self):
        assert _truncate("hello", 100) == "hello"

    def test_exact_limit_unchanged(self):
        text = "a" * 100
        assert _truncate(text, 100) == text

    def test_over_limit_truncated(self):
        text = "a" * 200
        result = _truncate(text, 100)
        assert result.startswith("a" * 100)
        assert "[truncated 100 chars]" in result

    def test_default_limit(self):
        short = "hello"
        assert _truncate(short) == short


class TestExecResult:
    def test_to_dict_basic(self):
        r = ExecResult(stdout="out", stderr="err", exit_code=0)
        d = r.to_dict()
        assert d["exit_code"] == 0
        assert d["stdout"] == "out"
        assert d["stderr"] == "err"

    def test_to_dict_empty_fields_omitted(self):
        r = ExecResult(stdout="", stderr="", exit_code=0)
        d = r.to_dict()
        assert "stdout" not in d
        assert "stderr" not in d

    def test_to_dict_timed_out(self):
        r = ExecResult(stdout="", stderr="", exit_code=-1, timed_out=True)
        d = r.to_dict()
        assert d["timed_out"] is True
        assert "message" in d

    def test_to_json(self):
        r = ExecResult(stdout="hello", stderr="", exit_code=0)
        parsed = json.loads(r.to_json())
        assert parsed["exit_code"] == 0
        assert parsed["stdout"] == "hello"


class TestWriteTempFile:
    def test_creates_file_with_content(self):
        path = write_temp_file("test content", suffix=".txt")
        try:
            assert os.path.exists(path)
            with open(path) as f:
                assert f.read() == "test content"
            assert path.endswith(".txt")
        finally:
            os.unlink(path)


class TestRunCommand:
    def test_echo(self):
        result = asyncio.get_event_loop().run_until_complete(
            run_command(["echo", "hello"])
        )
        assert result.exit_code == 0
        assert "hello" in result.stdout

    def test_nonexistent_binary(self):
        result = asyncio.get_event_loop().run_until_complete(
            run_command(["nonexistent_binary_xyz"])
        )
        assert result.exit_code == 127
        assert "not found" in result.stderr.lower()

    def test_timeout(self):
        result = asyncio.get_event_loop().run_until_complete(
            run_command(["sleep", "10"], timeout=1)
        )
        assert result.timed_out is True
        assert result.exit_code == -1

    def test_exit_code_preserved(self):
        result = asyncio.get_event_loop().run_until_complete(
            run_command(["sh", "-c", "exit 42"])
        )
        assert result.exit_code == 42


class TestRunShell:
    def test_echo(self):
        result = asyncio.get_event_loop().run_until_complete(
            run_shell("echo hello")
        )
        assert result.exit_code == 0
        assert "hello" in result.stdout

    def test_pipe(self):
        result = asyncio.get_event_loop().run_until_complete(
            run_shell("echo 'hello world' | tr 'h' 'H'")
        )
        assert result.exit_code == 0
        assert "Hello" in result.stdout

    def test_timeout(self):
        result = asyncio.get_event_loop().run_until_complete(
            run_shell("sleep 10", timeout=1)
        )
        assert result.timed_out is True


class TestToolFixes:
    @staticmethod
    def _ensure_mcp_stub():
        import sys
        import types

        try:
            import mcp.server.fastmcp  # noqa: F401
        except ModuleNotFoundError:
            class _DummyFastMCP:
                def __init__(self, *args, **kwargs):
                    pass

                def tool(self):
                    return lambda fn: fn

            mcp_mod = types.ModuleType("mcp")
            server_mod = types.ModuleType("mcp.server")
            fastmcp_mod = types.ModuleType("mcp.server.fastmcp")
            fastmcp_mod.FastMCP = _DummyFastMCP
            sys.modules.setdefault("mcp", mcp_mod)
            sys.modules.setdefault("mcp.server", server_mod)
            sys.modules.setdefault("mcp.server.fastmcp", fastmcp_mod)

    def test_hydra_http_post_form_allows_ampersand(self, monkeypatch):
        self._ensure_mcp_stub()
        from kali_mcp.tools import exploit

        captured_cmd: list[str] = []

        async def fake_run_command(cmd, *, timeout=300, stdin_data=None, env=None, workdir=None):
            captured_cmd.extend(cmd)
            return ExecResult(
                stdout="[80][http-post-form] host: 10.0.0.1   login: admin   password: secret\n",
                stderr="",
                exit_code=0,
            )

        monkeypatch.setattr(exploit, "run_command", fake_run_command)
        raw = asyncio.get_event_loop().run_until_complete(
            exploit.hydra_attack(
                target="10.0.0.1",
                service="http-post-form",
                userlist="user:admin",
                passlist="pass:p@ss$word",
                extra_flags='"/login:user=^USER^&pass=^PASS^:F=incorrect"',
            )
        )
        data = json.loads(raw)
        assert data["success"] is True
        assert "/login:user=^USER^&pass=^PASS^:F=incorrect" in captured_cmd

    def test_testssl_check_reads_jsonfile(self, monkeypatch):
        self._ensure_mcp_stub()
        from kali_mcp.tools import tls

        async def fake_run_command(cmd, *, timeout=300, stdin_data=None, env=None, workdir=None):
            for arg in cmd:
                if arg.startswith("--jsonfile="):
                    json_path = arg.split("=", 1)[1]
                    with open(json_path, "w") as f:
                        json.dump([{"id": "TLS1_2", "severity": "OK", "finding": "offered"}], f)
            return ExecResult(
                stdout="Start 2026-10-19 -->> 93.184.216.34:443 (example.com) <<--\n",
                stderr="",
                exit_code=0,
            )

        monkeypatch.setattr(tls, "run_command", fake_run_command)
        raw = asyncio.get_event_loop().run_until_complete(
            tls.testssl_check("example.com")
        )
        data = json.loads(raw)
        assert isinstance(data, list)
        assert data[0]["id"] == "TLS1_2"

    def test_gobuster_parses_dir_and_dns_output(self, monkeypatch, tmp_path):
        self._ensure_mcp_stub()
        from kali_mcp.tools import web

        wl = tmp_path / "words.txt"
        wl.write_text("admin\napi\n")
        captured_cmds: list[list[str]] = []

        async def fake_run_command(cmd, *, timeout=300, stdin_data=None, env=None, workdir=None):
            captured_cmds.append(cmd)
            if "dns" in cmd:
                return ExecResult(
                    stdout="Found: api.example.com\nFound: dev.example.com\n",
                    stderr="",
                    exit_code=0,
                )
            return ExecResult(
                stdout=(
                    "/admin                (Status: 301) [Size: 178] [--> http://example.com/admin/]\n"
                    "/api                  (Status: 200) [Size: 42]\n"
                ),
                stderr="",
                exit_code=0,
            )

        monkeypatch.setattr(web, "run_command", fake_run_command)

        dir_raw = asyncio.get_event_loop().run_until_complete(
            web.gobuster_scan("http://example.com", wordlist=str(wl), mode="dir", threads=25)
        )
        dir_data = json.loads(dir_raw)
        assert "25" in captured_cmds[0]
        assert dir_data["count"] == 2
        assert dir_data["results"][0] == {
            "path": "/admin",
            "status": "301",
            "size": "178",
            "redirect": "http://example.com/admin/",
        }
        assert dir_data["results"][1] == {"path": "/api", "status": "200", "size": "42"}

        dns_raw = asyncio.get_event_loop().run_until_complete(
            web.gobuster_scan("example.com", wordlist=str(wl), mode="dns", threads=20)
        )
        dns_data = json.loads(dns_raw)
        assert "--timeout" not in captured_cmds[1]
        assert "--domain" in captured_cmds[1]
        assert [r["path"] for r in dns_data["results"]] == ["api.example.com", "dev.example.com"]

    def test_ffuf_parses_jsonl_multiple_results(self, monkeypatch, tmp_path):
        self._ensure_mcp_stub()
        from kali_mcp.tools import web

        wl = tmp_path / "words.txt"
        wl.write_text("a\nb\n")

        async def fake_run_command(cmd, *, timeout=300, stdin_data=None, env=None, workdir=None):
            return ExecResult(
                stdout='{"input":{"FUZZ":"admin"},"status":200,"length":123}\n{"input":{"FUZZ":"login"},"status":302,"length":0}\n',
                stderr="",
                exit_code=0,
            )

        monkeypatch.setattr(web, "run_command", fake_run_command)
        raw = asyncio.get_event_loop().run_until_complete(
            web.ffuf_fuzz("http://example.com/FUZZ", wordlist=str(wl))
        )
        data = json.loads(raw)
        assert data["count"] == 2
        assert data["results"][0]["status"] == 200
        assert data["results"][1]["status"] == 302

    def test_curl_request_redirect_headers_and_hping3_stderr(self, monkeypatch):
        self._ensure_mcp_stub()
        from kali_mcp.tools import network

        async def fake_curl(cmd, *, timeout=300, stdin_data=None, env=None, workdir=None):
            return ExecResult(
                stdout=(
                    "HTTP/1.1 301 Moved Permanently\r\nLocation: https://example.com/\r\n\r\n"
                    "HTTP/2 200 \r\ncontent-type: text/html\r\n\r\n"
                    "<html>hello</html>\n---CURL_STATUS:200---\n"
                ),
                stderr="",
                exit_code=0,
            )

        monkeypatch.setattr(network, "run_command", fake_curl)
        curl_raw = asyncio.get_event_loop().run_until_complete(
            network.curl_request("http://example.com")
        )
        curl_data = json.loads(curl_raw)
        assert curl_data["status_code"] == 200
        assert "HTTP/2 200" in curl_data["headers"]
        assert curl_data["body"].strip() == "<html>hello</html>"

        async def fake_hping(cmd, *, timeout=300, stdin_data=None, env=None, workdir=None):
            return ExecResult(
                stdout="HPING 10.0.0.1 (eth0 10.0.0.1): S set, 40 headers + 0 data bytes",
                stderr="--- 10.0.0.1 hping statistic ---\n3 packets transmitted, 3 packets received, 0% packet loss",
                exit_code=0,
            )

        monkeypatch.setattr(network, "run_command", fake_hping)
        hping_raw = asyncio.get_event_loop().run_until_complete(
            network.hping3_probe("10.0.0.1", port=80, count=3)
        )
        hping_data = json.loads(hping_raw)
        assert "0% packet loss" in hping_data["output"]

    def test_check_job_rejects_traversal_and_empty_targets(self):
        self._ensure_mcp_stub()
        from kali_mcp.tools import recon, shell, web

        bad_job = json.loads(
            asyncio.get_event_loop().run_until_complete(
                shell.check_job("../../etc/passwd")
            )
        )
        assert "error" in bad_job

        empty_dnsx = json.loads(
            asyncio.get_event_loop().run_until_complete(
                recon.dnsx_resolve([])
            )
        )
        assert empty_dnsx["results"] == []

        empty_httpx = json.loads(
            asyncio.get_event_loop().run_until_complete(
                web.httpx_probe([])
            )
        )
        assert empty_httpx["count"] == 0

