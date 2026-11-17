"""CLI tests for `sot-validator serve` token, remote-bind and start-up wiring."""

from __future__ import annotations

import json
import re
import socket
import threading
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from sot_validator.cli import workbench as cli_workbench
from sot_validator.cli import _workbench_url, main

URL_RE = re.compile(r"(http://127\.0\.0\.1:(\d+)/)#token=(\S+)")


@pytest.fixture(autouse=True)
def _run_in_tmp_path(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    # `serve` without --snapshot writes default fixture snapshots to ./output.
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("SOT_WORKBENCH_TOKEN", raising=False)


def test_serve_prints_token_url_once_and_supplied_token_verbatim(
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc = main(
        ["serve", "--host", "127.0.0.1", "--port", "0", "--token", "cli-tok_1", "--once"]
    )
    assert rc == 0
    out, err = capsys.readouterr()
    matches = URL_RE.findall(out)
    assert len(matches) == 1
    assert matches[0][2] == "cli-tok_1"
    assert "?token=" not in out
    assert "cli-tok_1" not in err


def test_serve_generates_and_prints_a_fresh_token(
    capsys: pytest.CaptureFixture[str],
) -> None:
    tokens = []
    for _ in range(2):
        assert main(["serve", "--host", "127.0.0.1", "--port", "0", "--once"]) == 0
        match = URL_RE.search(capsys.readouterr().out)
        assert match is not None
        tokens.append(match.group(3))
    assert all(len(token) >= 32 for token in tokens)
    assert tokens[0] != tokens[1]


def test_serve_check_does_not_print_token(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(
        ["serve", "--host", "127.0.0.1", "--port", "0", "--token", "chk-tok", "--check"]
    )
    assert rc == 0
    out, err = capsys.readouterr()
    assert "chk-tok" not in out + err


@pytest.mark.parametrize("host", ["0.0.0.0", "", "10.9.1.2"])
def test_serve_refuses_non_loopback_host_cleanly(
    host: str, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = main(["serve", "--host", host, "--port", "0", "--token", "rf-tok", "--check"])
    assert rc == 2
    out, err = capsys.readouterr()
    assert "--allow-remote" in err
    assert "Traceback" not in err
    assert "rf-tok" not in out + err


def test_serve_allow_remote_binds_wildcard_host(
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc = main(["serve", "--host", "0.0.0.0", "--port", "0", "--allow-remote", "--check"])
    assert rc == 0
    assert capsys.readouterr().err == ""


def test_serve_reports_port_in_use_cleanly(capsys: pytest.CaptureFixture[str]) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen(1)
        port = busy.getsockname()[1]
        rc = main(
            ["serve", "--host", "127.0.0.1", "--port", str(port), "--token", "busy-tok", "--check"]
        )
    assert rc == 2
    out, err = capsys.readouterr()
    assert err.startswith("error: cannot bind the workbench")
    assert "busy-tok" not in out + err


@pytest.mark.parametrize("bad_token", ["", "has space", "trail\n", "ctl\x01x", "café"])
def test_serve_rejects_bad_token_without_echoing_it(
    bad_token: str, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = main(["serve", "--host", "127.0.0.1", "--port", "0", "--token", bad_token, "--check"])
    assert rc == 2
    out, err = capsys.readouterr()
    assert err.startswith("error: --token rejected")
    if bad_token:
        assert bad_token not in out + err
    assert "Traceback" not in err


def test_workbench_url_brackets_ipv6_and_maps_wildcards() -> None:
    assert _workbench_url(("::1", 5100, 0, 0)) == "http://[::1]:5100/"
    assert _workbench_url(("0.0.0.0", 5100)) == "http://127.0.0.1:5100/"
    assert _workbench_url(("::", 5100, 0, 0)) == "http://127.0.0.1:5100/"
    assert _workbench_url(("127.0.0.1", 5100)) == "http://127.0.0.1:5100/"


def test_printed_token_url_authenticates_writes(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    servers: list[Any] = []
    real_create = cli_workbench.create_workbench_server

    def _capture(*args: Any, **kwargs: Any) -> Any:
        server = real_create(*args, **kwargs)
        servers.append(server)
        return server

    monkeypatch.setattr(cli_workbench, "create_workbench_server", _capture)
    result: list[int] = []
    thread = threading.Thread(
        target=lambda: result.append(main(["serve", "--host", "127.0.0.1", "--port", "0"])),
        daemon=True,
    )
    thread.start()
    try:
        match = None
        for _ in range(100):
            match = URL_RE.search(capsys.readouterr().out)
            if match:
                break
            thread.join(timeout=0.05)
        assert match is not None
        base_url, token = match.group(1).rstrip("/"), match.group(3)

        state_before = urlopen(f"{base_url}/api/state", timeout=5).read()
        device_id = json.loads(state_before)["site"]["devices"][0]["device_id"]
        body = json.dumps(
            {"target_type": "NetworkDevice", "target_id": device_id, "room": "MDF-CLI"}
        ).encode("utf-8")

        def _post(auth: str | None) -> int:
            headers = {"Content-Type": "application/json", "Origin": base_url}
            if auth is not None:
                headers["Authorization"] = auth
            req = Request(f"{base_url}/api/items/patch", data=body, headers=headers, method="POST")
            try:
                with urlopen(req, timeout=5) as resp:
                    return resp.status
            except HTTPError as exc:
                return exc.code

        assert _post(None) == 401
        assert _post(f"Bearer {token}") == 200
        audit = json.loads(urlopen(f"{base_url}/api/audit-log", timeout=5).read())
        assert any(entry["target_id"] == device_id for entry in audit["audit_log"])
    finally:
        for server in servers:
            server.shutdown()
        thread.join(timeout=5)
    assert result == [0]


def _serve_once(argv: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    rc = main(["serve", "--host", "127.0.0.1", "--port", "0", *argv])
    out, err = capsys.readouterr()
    return rc, out, err


def _printed_token(out: str) -> str:
    matches = URL_RE.findall(out)
    assert len(matches) == 1
    return matches[0][2]


def test_serve_token_file_token_is_printed_and_authenticates_writes(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    token_file = tmp_path / "tok.txt"
    token_file.write_text("file-tok\n", encoding="utf-8")
    rc, out, err = _serve_once(["--token-file", str(token_file), "--once"], capsys)
    assert rc == 0
    assert _printed_token(out) == "file-tok"
    assert "file-tok" not in err

    servers: list[Any] = []
    real_create = cli_workbench.create_workbench_server

    def _capture(*args: Any, **kwargs: Any) -> Any:
        server = real_create(*args, **kwargs)
        servers.append(server)
        return server

    monkeypatch.setattr(cli_workbench, "create_workbench_server", _capture)
    result: list[int] = []
    thread = threading.Thread(
        target=lambda: result.append(
            main(["serve", "--host", "127.0.0.1", "--port", "0", "--token-file", str(token_file)])
        ),
        daemon=True,
    )
    thread.start()
    try:
        match = None
        for _ in range(100):
            match = URL_RE.search(capsys.readouterr().out)
            if match:
                break
            thread.join(timeout=0.05)
        assert match is not None
        base_url, token = match.group(1).rstrip("/"), match.group(3)
        assert token == "file-tok"
        state = json.loads(urlopen(f"{base_url}/api/state", timeout=5).read())
        device_id = state["site"]["devices"][0]["device_id"]
        req = Request(
            f"{base_url}/api/items/patch",
            data=json.dumps(
                {"target_type": "NetworkDevice", "target_id": device_id, "room": "MDF-FILE"}
            ).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Origin": base_url,
                "Authorization": f"Bearer {token}",
            },
            method="POST",
        )
        with urlopen(req, timeout=5) as resp:
            assert resp.status == 200
    finally:
        for server in servers:
            server.shutdown()
        thread.join(timeout=5)
    assert result == [0]


@pytest.mark.parametrize(
    ("content", "expected"),
    [("crlf-tok\r\n", "crlf-tok"), ("bare-tok", "bare-tok")],
)
def test_serve_token_file_drops_only_one_trailing_newline(
    content: str, expected: str, tmp_path: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    token_file = tmp_path / "tok.txt"
    token_file.write_bytes(content.encode("utf-8"))
    rc, out, _ = _serve_once(["--token-file", str(token_file), "--once"], capsys)
    assert rc == 0
    assert _printed_token(out) == expected


def test_serve_token_file_with_two_newlines_is_rejected(
    tmp_path: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    token_file = tmp_path / "tok.txt"
    token_file.write_text("two-nl-tok\n\n", encoding="utf-8")
    rc, out, err = _serve_once(["--token-file", str(token_file), "--check"], capsys)
    assert rc == 2
    assert err.startswith("error: --token-file rejected")
    assert "two-nl-tok" not in out + err


def test_serve_env_token_and_precedence(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SOT_WORKBENCH_TOKEN", "env-tok")
    rc, out, err = _serve_once(["--once"], capsys)
    assert rc == 0
    assert _printed_token(out) == "env-tok"
    assert "env-tok" not in err

    rc, out, _ = _serve_once(["--token", "cli-tok", "--once"], capsys)
    assert rc == 0
    assert _printed_token(out) == "cli-tok"

    token_file = tmp_path / "tok.txt"
    token_file.write_text("file-tok\n", encoding="utf-8")
    rc, out, _ = _serve_once(["--token-file", str(token_file), "--once"], capsys)
    assert rc == 0
    assert _printed_token(out) == "file-tok"


def test_serve_empty_env_token_counts_as_unset(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SOT_WORKBENCH_TOKEN", "")
    rc, out, _ = _serve_once(["--once"], capsys)
    assert rc == 0
    assert len(_printed_token(out)) >= 32


def test_serve_rejects_token_and_token_file_together(
    tmp_path: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    token_file = tmp_path / "tok.txt"
    token_file.write_text("both-file-tok\n", encoding="utf-8")
    rc, out, err = _serve_once(
        ["--token", "both-cli-tok", "--token-file", str(token_file), "--check"], capsys
    )
    assert rc == 2
    assert err.startswith("error:")
    assert len(err.strip().splitlines()) == 1
    assert "--token-file" in err
    assert "both-cli-tok" not in out + err
    assert "both-file-tok" not in out + err


def test_serve_missing_token_file_reports_cleanly(
    tmp_path: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    rc, _, err = _serve_once(["--token-file", str(tmp_path / "absent.txt"), "--check"], capsys)
    assert rc == 2
    assert err.startswith("error: --token-file")
    assert len(err.strip().splitlines()) == 1
    assert "Traceback" not in err


def test_serve_non_utf8_token_file_reports_cleanly(
    tmp_path: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    token_file = tmp_path / "tok.bin"
    token_file.write_bytes(b"\xff\xfesecret\n")
    rc, out, err = _serve_once(["--token-file", str(token_file), "--check"], capsys)
    assert rc == 2
    assert err.startswith("error: --token-file")
    assert "secret" not in out + err
    assert "Traceback" not in err


def test_serve_token_file_directory_reports_cleanly(
    tmp_path: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    rc, _, err = _serve_once(["--token-file", str(tmp_path), "--check"], capsys)
    assert rc == 2
    assert err.startswith("error: --token-file")
    assert "Traceback" not in err


def test_serve_bad_token_file_contents_are_not_echoed(
    tmp_path: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    token_file = tmp_path / "tok.txt"
    token_file.write_text("has space\n", encoding="utf-8")
    rc, out, err = _serve_once(["--token-file", str(token_file), "--check"], capsys)
    assert rc == 2
    assert err.startswith("error: --token-file rejected")
    assert "has space" not in out + err
    assert "Traceback" not in err


@pytest.mark.parametrize("bad_token", ["bad tok", "trail\n", "ctl\x01x"])
def test_serve_bad_env_token_is_not_echoed(
    bad_token: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SOT_WORKBENCH_TOKEN", bad_token)
    rc, out, err = _serve_once(["--check"], capsys)
    assert rc == 2
    assert err.startswith("error: SOT_WORKBENCH_TOKEN rejected")
    assert bad_token not in out + err


def test_serve_quiet_token_omits_token_from_output(
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc, out, err = _serve_once(["--token", "q-tok", "--quiet-token", "--once"], capsys)
    assert rc == 0
    assert "Workbench listening; open http://127.0.0.1:" in out
    assert "#token=" not in out
    assert "q-tok" not in out + err


def test_serve_quiet_token_accepts_env_token(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SOT_WORKBENCH_TOKEN", "q-env-tok")
    rc, out, err = _serve_once(["--quiet-token", "--once"], capsys)
    assert rc == 0
    assert "#token=" not in out
    assert "q-env-tok" not in out + err


@pytest.mark.parametrize("env_value", [None, ""])
def test_serve_quiet_token_requires_supplied_token(
    env_value: str | None, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    if env_value is not None:
        monkeypatch.setenv("SOT_WORKBENCH_TOKEN", env_value)
    rc, out, err = _serve_once(["--quiet-token", "--check"], capsys)
    assert rc == 2
    assert err.startswith("error:")
    assert len(err.strip().splitlines()) == 1
    assert "#token=" not in out


def test_serve_rejects_empty_allowed_host(capsys: pytest.CaptureFixture[str]) -> None:
    rc, _, err = _serve_once(["--allowed-host", "", "--check"], capsys)
    assert rc == 2
    assert err.startswith("error: --allowed-host rejected")


def test_serve_passes_allowed_hosts_to_security_config(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    seen: list[Any] = []
    real_create = cli_workbench.create_workbench_server

    def _capture(*args: Any, **kwargs: Any) -> Any:
        server = real_create(*args, **kwargs)
        seen.append(server)
        return server

    monkeypatch.setattr(cli_workbench, "create_workbench_server", _capture)
    rc, _, _ = _serve_once(
        ["--allowed-host", "WB.Example", "--allowed-host", "[fd00::5]", "--check"], capsys
    )
    assert rc == 0
    assert seen[0].security.allowed_hosts == ("wb.example", "fd00::5")
    assert {"wb.example", "fd00::5", "localhost"} <= seen[0].allowed_hosts


def test_serve_other_value_error_is_not_reported_as_bind_refusal(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def _boom(*args: Any, **kwargs: Any) -> Any:
        raise ValueError("boom")

    monkeypatch.setattr(cli_workbench, "create_workbench_server", _boom)
    rc, _, err = _serve_once(["--token", "boom-tok", "--check"], capsys)
    assert rc == 2
    assert len(err.strip().splitlines()) == 1
    assert "boom" in err
    assert "refusing to bind" not in err
    assert "--allow-remote" not in err
    assert "boom-tok" not in err
