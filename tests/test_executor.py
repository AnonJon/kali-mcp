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
