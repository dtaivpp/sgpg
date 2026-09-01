"""XDG-style filesystem locations for sgpg's own (non-secret-key) state.

Nothing under these paths is ever a private key or plaintext message
body -- see security.py and the module docstrings in contacts/ and
signal/ for what is and isn't allowed to be written here.
"""

from __future__ import annotations

import os
from pathlib import Path


def config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME")
    root = Path(base) if base else Path.home() / ".config"
    return root / "sgpg"


def data_dir() -> Path:
    base = os.environ.get("XDG_DATA_HOME")
    root = Path(base) if base else Path.home() / ".local" / "share"
    return root / "sgpg"


def contacts_path() -> Path:
    return config_dir() / "contacts.toml"


def metadata_db_path() -> Path:
    return data_dir() / "metadata.db"


def signal_socket_path() -> Path:
    return data_dir() / "signal-cli.sock"
