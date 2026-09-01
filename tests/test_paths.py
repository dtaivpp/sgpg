from __future__ import annotations

from pathlib import Path

import pytest

from sgpg import paths


def test_config_dir_respects_xdg_config_home(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert paths.config_dir() == tmp_path / "sgpg"


def test_config_dir_falls_back_to_home_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    assert paths.config_dir() == Path.home() / ".config" / "sgpg"


def test_data_dir_respects_xdg_data_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    assert paths.data_dir() == tmp_path / "sgpg"


def test_derived_paths_live_under_their_base_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    assert paths.contacts_path() == tmp_path / "sgpg" / "contacts.toml"
    assert paths.metadata_db_path() == tmp_path / "sgpg" / "metadata.db"
    assert paths.signal_socket_path() == tmp_path / "sgpg" / "signal-cli.sock"
