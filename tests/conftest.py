"""Shared pytest fixtures.

Tests never touch the user's real GnuPG keyring: every GPG-backed test
uses an isolated, temporary GNUPGHOME with disposable test keys
generated fresh for the test session.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import textwrap
from collections.abc import Iterator
from pathlib import Path

import pytest

from sgpg.crypto.gpg import GPG


def _generate_test_key(gnupghome: Path, *, name: str, email: str) -> str:
    """Generate a disposable test key and return its fingerprint."""
    batch = textwrap.dedent(
        f"""\
        %no-protection
        Key-Type: eddsa
        Key-Curve: ed25519
        Key-Usage: sign
        Subkey-Type: ecdh
        Subkey-Curve: cv25519
        Subkey-Usage: encrypt
        Name-Real: {name}
        Name-Email: {email}
        Expire-Date: 0
        %commit
        """
    )
    env = {**os.environ, "GNUPGHOME": str(gnupghome)}
    subprocess.run(
        ["gpg", "--batch", "--gen-key"],
        input=batch.encode("utf-8"),
        env=env,
        check=True,
        capture_output=True,
        timeout=60,
    )
    proc = subprocess.run(
        ["gpg", "--batch", "--with-colons", "--fingerprint", "--list-secret-keys", email],
        env=env,
        check=True,
        capture_output=True,
        timeout=30,
    )
    for line in proc.stdout.decode("utf-8").splitlines():
        fields = line.split(":")
        if fields[0] == "fpr":
            return fields[9]
    raise RuntimeError(f"could not find fingerprint for freshly generated key {email!r}")


@pytest.fixture(scope="session")
def gnupg_home() -> Iterator[Path]:
    # gpg-agent's Unix socket path (GNUPGHOME/S.gpg-agent) has to fit in
    # sun_path (~104-108 bytes), which pytest's own tmp_path is often too
    # deeply nested for. Use a short directory straight under /tmp instead.
    raw = tempfile.mkdtemp(prefix="sgpg-t-", dir="/tmp")
    home = Path(raw)
    home.chmod(0o700)
    try:
        yield home
    finally:
        subprocess.run(
            ["gpgconf", "--kill", "gpg-agent"],
            env={**os.environ, "GNUPGHOME": str(home)},
            check=False,
            capture_output=True,
        )
        shutil.rmtree(home, ignore_errors=True)


@pytest.fixture(scope="session")
def self_fingerprint(gnupg_home: Path) -> str:
    return _generate_test_key(gnupg_home, name="Test Self", email="self@sgpg.test")


@pytest.fixture(scope="session")
def alice_fingerprint(gnupg_home: Path) -> str:
    return _generate_test_key(gnupg_home, name="Test Alice", email="alice@sgpg.test")


@pytest.fixture(scope="session")
def gpg_adapter(gnupg_home: Path, self_fingerprint: str, alice_fingerprint: str) -> GPG:
    # Depending on both fingerprints ensures both test keys exist before
    # any test using this adapter runs.
    return GPG(gnupghome=str(gnupg_home))


@pytest.fixture
def tmp_contacts_path(tmp_path: Path) -> Path:
    return tmp_path / "contacts.toml"


@pytest.fixture
def tmp_history_path(tmp_path: Path) -> Path:
    return tmp_path / "history.db"
