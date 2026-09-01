"""Security-invariant tests (README build phase 5).

Covers things that are easy to silently regress: plaintext leaking into
temp files or argv, and the fail-closed behavior for revoked/expired/
missing keys that stand between an attacker and "the wrapper trusted a
key it shouldn't have."
"""

from __future__ import annotations

import ast
import itertools
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sgpg import security
from sgpg.contacts.resolver import ContactResolver, UnresolvedContactError, UnusableKeyError
from sgpg.contacts.store import ContactStore
from sgpg.crypto.gpg import KeyInfo

SRC = Path(__file__).resolve().parent.parent / "src" / "sgpg"

FPR = "0123456789ABCDEF0123456789ABCDEF01234567"


def _imported_module_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module.split(".")[0])
    return names


def test_gpg_module_never_imports_tempfile() -> None:
    """Invariant #2: no plaintext temporary files, ever."""
    assert "tempfile" not in _imported_module_names(SRC / "crypto" / "gpg.py")


def _uses_shell_true(tree: ast.AST) -> bool:
    return any(
        isinstance(node, ast.keyword)
        and node.arg == "shell"
        and isinstance(node.value, ast.Constant)
        and node.value.value is True
        for node in ast.walk(tree)
    )


def _sets_trust_model_always(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if not isinstance(node, (ast.List, ast.Tuple)):
            continue
        for a, b in itertools.pairwise(node.elts):
            if (
                isinstance(a, ast.Constant)
                and a.value == "--trust-model"
                and isinstance(b, ast.Constant)
                and b.value == "always"
            ):
                return True
    return False


def test_no_module_ever_uses_shell_true() -> None:
    """Every subprocess call must use an argv list -- never a shell string.

    Checks real ``shell=`` keyword arguments via the AST, not the source
    text, so this doesn't just match this test file's own docstrings.
    """
    for path in SRC.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        assert not _uses_shell_true(tree), f"{path} uses shell=True"


def test_no_module_sets_trust_model_always() -> None:
    """GnuPG's own trust machinery must stay in control."""
    for path in SRC.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        assert not _sets_trust_model_always(tree), f"{path} may bypass GnuPG trust"


def test_send_command_has_no_plaintext_option_or_argument() -> None:
    """cli.py's send command must only ever read plaintext from stdin."""
    tree = ast.parse((SRC / "cli.py").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "send":
            arg_names = {a.arg for a in node.args.args}
            assert "message" not in arg_names
            assert "plaintext" not in arg_names
            assert "text" not in arg_names


class TestSecurityHardening:
    def test_disable_core_dumps_makes_core_dumps_disabled_true(self) -> None:
        if security.resource is None:
            pytest.skip("resource module unavailable on this platform")
        security.disable_core_dumps()
        assert security.core_dumps_disabled()

    def test_harden_process_sets_conservative_log_level(self) -> None:
        logging.getLogger().setLevel(logging.NOTSET)
        security.harden_process()
        assert security.debug_logging_disabled()


def _fake_key(
    *,
    fingerprint: str = FPR,
    can_encrypt: bool = True,
    revoked: bool = False,
    expired: bool = False,
) -> KeyInfo:
    return KeyInfo(
        fingerprint=fingerprint,
        uids=("Test <test@example.com>",),
        can_encrypt=can_encrypt,
        can_sign=True,
        revoked=revoked,
        expired=expired,
        expiry=datetime(2099, 1, 1, tzinfo=UTC),
    )


@dataclass
class _FakeGPG:
    """Duck-typed stand-in for GPG so resolver failure paths don't need a real keyring."""

    key: KeyInfo | None

    async def fingerprint_info(self, fingerprint: str) -> KeyInfo | None:
        return self.key


class TestContactResolverFailsClosed:
    """README phase 5: missing/revoked/expired keys must all fail closed."""

    def _store_with_alice(self, tmp_path: Path, fingerprint: str = FPR) -> ContactStore:
        store = ContactStore(tmp_path / "contacts.toml")
        store.add_contact("alice", signal_number="+15551234567", gpg_fingerprint=fingerprint)
        return store

    @pytest.mark.asyncio
    async def test_valid_key_resolves(self, tmp_path: Path) -> None:
        store = self._store_with_alice(tmp_path)
        resolver = ContactResolver(store, _FakeGPG(_fake_key()))  # type: ignore[arg-type]
        resolved = await resolver.resolve("alice")
        assert resolved.key.fingerprint == FPR

    @pytest.mark.asyncio
    async def test_revoked_key_is_rejected(self, tmp_path: Path) -> None:
        store = self._store_with_alice(tmp_path)
        resolver = ContactResolver(store, _FakeGPG(_fake_key(revoked=True)))  # type: ignore[arg-type]
        with pytest.raises(UnusableKeyError, match="revoked"):
            await resolver.resolve("alice")

    @pytest.mark.asyncio
    async def test_expired_key_is_rejected(self, tmp_path: Path) -> None:
        store = self._store_with_alice(tmp_path)
        resolver = ContactResolver(store, _FakeGPG(_fake_key(expired=True)))  # type: ignore[arg-type]
        with pytest.raises(UnusableKeyError, match="expired"):
            await resolver.resolve("alice")

    @pytest.mark.asyncio
    async def test_non_encryption_capable_key_is_rejected(self, tmp_path: Path) -> None:
        store = self._store_with_alice(tmp_path)
        resolver = ContactResolver(store, _FakeGPG(_fake_key(can_encrypt=False)))  # type: ignore[arg-type]
        with pytest.raises(UnusableKeyError, match="encryption subkey"):
            await resolver.resolve("alice")

    @pytest.mark.asyncio
    async def test_missing_key_is_rejected(self, tmp_path: Path) -> None:
        """Fingerprint set on the contact, but the key isn't in the keyring
        (e.g. a wrong/backup YubiKey whose keys were never imported)."""
        store = self._store_with_alice(tmp_path)
        resolver = ContactResolver(store, _FakeGPG(None))  # type: ignore[arg-type]
        with pytest.raises(UnusableKeyError, match="not in your keyring"):
            await resolver.resolve("alice")

    @pytest.mark.asyncio
    async def test_unknown_contact_is_rejected(self, tmp_path: Path) -> None:
        store = ContactStore(tmp_path / "contacts.toml")
        resolver = ContactResolver(store, _FakeGPG(_fake_key()))  # type: ignore[arg-type]
        with pytest.raises(UnresolvedContactError):
            await resolver.resolve("ghost")

    @pytest.mark.asyncio
    async def test_contact_without_a_fingerprint_is_rejected(self, tmp_path: Path) -> None:
        store = ContactStore(tmp_path / "contacts.toml")
        store.add_contact("alice", signal_number="+15551234567")
        resolver = ContactResolver(store, _FakeGPG(_fake_key()))  # type: ignore[arg-type]
        with pytest.raises(UnresolvedContactError, match="no gpg fingerprint"):
            await resolver.resolve("alice")
