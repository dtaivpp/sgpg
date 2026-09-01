"""CLI smoke tests.

Exercises the Typer wiring end-to-end against the isolated test GnuPG
keyring. Commands that require a live signal-cli daemon (send, chat,
read-while-connected) aren't run here since no daemon is available in
CI -- their business logic is covered directly in test_app.py instead.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sgpg.cli import app

runner = CliRunner()


def _global_args(
    *, gnupghome: str, contacts_path: Path, history_path: Path, socket_path: Path
) -> list[str]:
    return [
        "--gnupghome",
        gnupghome,
        "--contacts-path",
        str(contacts_path),
        "--history-path",
        str(history_path),
        "--socket-path",
        str(socket_path),
        # Never let the test suite spawn a real signal-cli daemon subprocess:
        # slow, non-hermetic, and (being detached) leaks background processes.
        # Auto-daemon wiring itself is covered by mocks in test_signal_client.py.
        "--no-auto-daemon",
    ]


@pytest.fixture
def cli_env(
    gnupg_home: Path, tmp_contacts_path: Path, tmp_history_path: Path, tmp_path: Path
) -> list[str]:
    return _global_args(
        gnupghome=str(gnupg_home),
        contacts_path=tmp_contacts_path,
        history_path=tmp_history_path,
        socket_path=tmp_path / "no-such.sock",
    )


def test_contact_list_on_empty_store(cli_env: list[str]) -> None:
    result = runner.invoke(app, [*cli_env, "contact", "list"])
    assert result.exit_code == 0, result.output
    assert "Name" in result.output


def test_contact_add_interactive_flow_then_list_and_show(
    cli_env: list[str], alice_fingerprint: str
) -> None:
    add_result = runner.invoke(
        app,
        [
            *cli_env,
            "contact",
            "add",
            "alice",
            "--signal-number",
            "+15551234567",
            "--query",
            "Test Alice",
        ],
        input="1\ny\n",
    )
    assert add_result.exit_code == 0, add_result.output
    assert "added alice" in add_result.output

    list_result = runner.invoke(app, [*cli_env, "contact", "list"])
    assert "alice" in list_result.output
    assert alice_fingerprint in list_result.output

    show_result = runner.invoke(app, [*cli_env, "contact", "show", "alice"])
    assert show_result.exit_code == 0, show_result.output

    verify_result = runner.invoke(app, [*cli_env, "contact", "verify", "alice"])
    assert verify_result.exit_code == 0, verify_result.output
    assert "usable" in verify_result.output


def test_contact_add_falls_back_to_manual_entry_without_daemon_or_flags(
    cli_env: list[str],
) -> None:
    """No --signal-number/--signal-uuid and no daemon running: prompt instead."""
    result = runner.invoke(
        app,
        [*cli_env, "contact", "add", "dave", "--query", "Test Alice"],
        input="+15550001111\n1\ny\n",
    )
    assert result.exit_code == 0, result.output
    assert "can't reach the Signal daemon" in result.output

    list_result = runner.invoke(app, [*cli_env, "contact", "list"])
    assert "+15550001111" in list_result.output


def test_contact_add_declining_confirmation_does_not_save(cli_env: list[str]) -> None:
    result = runner.invoke(
        app,
        [*cli_env, "contact", "add", "bob", "--signal-number", "+15559999999", "--query", "Test"],
        input="1\nn\n",
    )
    assert result.exit_code != 0

    list_result = runner.invoke(app, [*cli_env, "contact", "list"])
    assert "bob" not in list_result.output


def test_contact_set_key_rejects_invalid_fingerprint(cli_env: list[str]) -> None:
    runner.invoke(app, [*cli_env, "contact", "add", "carol", "--signal-number", "+15551110000"])
    result = runner.invoke(app, [*cli_env, "contact", "set-key", "carol", "not-a-fingerprint"])
    assert result.exit_code != 0


def test_identity_set_requires_a_secret_key(cli_env: list[str]) -> None:
    unknown = "A" * 40
    result = runner.invoke(app, [*cli_env, "identity", "set", unknown])
    assert result.exit_code != 0
    assert "no secret key" in result.output


def test_identity_set_and_show_round_trip(cli_env: list[str], self_fingerprint: str) -> None:
    set_result = runner.invoke(app, [*cli_env, "identity", "set", self_fingerprint])
    assert set_result.exit_code == 0, set_result.output

    show_result = runner.invoke(app, [*cli_env, "identity", "show"])
    assert show_result.exit_code == 0, show_result.output
    assert self_fingerprint in show_result.output


def test_identity_show_before_set_fails_clearly(cli_env: list[str]) -> None:
    result = runner.invoke(app, [*cli_env, "identity", "show"])
    assert result.exit_code != 0
    assert "identity set" in result.output


def test_identity_set_account_rejects_bad_number(cli_env: list[str]) -> None:
    result = runner.invoke(app, [*cli_env, "identity", "set-account", "not-a-number"])
    assert result.exit_code != 0


def test_identity_set_account_and_show_round_trip(cli_env: list[str]) -> None:
    set_result = runner.invoke(app, [*cli_env, "identity", "set-account", "+15551234567"])
    assert set_result.exit_code == 0, set_result.output

    show_result = runner.invoke(app, [*cli_env, "identity", "show"])
    assert show_result.exit_code == 0, show_result.output
    assert "+15551234567" in show_result.output


def test_persisted_account_becomes_the_default_for_daemon_error_hints(
    cli_env: list[str],
) -> None:
    """A persisted Signal account should flow through to --account without
    having to be passed on every command."""
    runner.invoke(app, [*cli_env, "identity", "set-account", "+15551234567"])
    # send fails (no daemon) but must not crash while resolving --account.
    result = runner.invoke(app, [*cli_env, "send", "nobody"], input="hi\n")
    assert result.exit_code != 0
    assert "daemon" in result.output.lower()


def test_doctor_reports_identity_once_set(cli_env: list[str], self_fingerprint: str) -> None:
    runner.invoke(app, [*cli_env, "identity", "set", self_fingerprint])
    result = runner.invoke(app, [*cli_env, "doctor"])
    assert result.exit_code == 0, result.output
    assert self_fingerprint in result.output


def test_doctor_runs_without_a_daemon_or_identity(cli_env: list[str]) -> None:
    result = runner.invoke(app, [*cli_env, "doctor"])
    assert result.exit_code == 0, result.output
    assert "gpg found" in result.output
    assert "Identity:" in result.output
    assert "Plaintext persistence:" in result.output


def test_key_import_public_key_file(
    cli_env: list[str], gnupg_home: Path, alice_fingerprint: str, tmp_path: Path
) -> None:
    export = subprocess.run(
        ["gpg", "--batch", "--armor", "--export", alice_fingerprint],
        env={**os.environ, "GNUPGHOME": str(gnupg_home)},
        check=True,
        capture_output=True,
    )
    key_file = tmp_path / "alice.asc"
    key_file.write_bytes(export.stdout)

    fresh_home = tmp_path / "fresh-gnupghome"
    fresh_home.mkdir(mode=0o700)
    result = runner.invoke(
        app,
        [
            "--gnupghome",
            str(fresh_home),
            "key",
            "import",
            str(key_file),
        ],
    )
    assert result.exit_code == 0, result.output
    assert alice_fingerprint in result.output


def test_send_without_a_running_daemon_fails_clearly(cli_env: list[str]) -> None:
    result = runner.invoke(app, [*cli_env, "send", "alice"], input="hello\n")
    assert result.exit_code != 0
    assert "daemon" in result.output.lower()
