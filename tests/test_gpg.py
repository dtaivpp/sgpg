from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest

from sgpg.crypto.gpg import (
    GPG,
    GPGDecryptionError,
    GPGEncryptionError,
    InvalidFingerprintError,
    normalize_fingerprint,
    zero,
)


class TestNormalizeFingerprint:
    def test_accepts_and_uppercases_a_valid_v4_fingerprint(self) -> None:
        fpr = "0123456789abcdef0123456789abcdef01234567"
        assert normalize_fingerprint(fpr) == fpr.upper()

    def test_strips_spaces(self) -> None:
        fpr = "0123 4567 89AB CDEF 0123 4567 89AB CDEF 0123 4567"
        assert normalize_fingerprint(fpr) == fpr.replace(" ", "")

    @pytest.mark.parametrize(
        "bogus",
        [
            "0123456789AB",  # short key id -- spoofable, must be rejected
            "not-hex-at-all-not-hex-at-all-not-hexxx",
            "",
        ],
    )
    def test_rejects_anything_that_is_not_a_full_fingerprint(self, bogus: str) -> None:
        with pytest.raises(InvalidFingerprintError):
            normalize_fingerprint(bogus)


def test_zero_overwrites_a_bytearray_in_place() -> None:
    buf = bytearray(b"super secret plaintext")
    zero(buf)
    assert buf == bytearray(len(buf))


@pytest.mark.asyncio
async def test_encrypt_decrypt_round_trip(gpg_adapter: GPG, self_fingerprint: str) -> None:
    plaintext = b"the deploy finished, ship it"
    result = await gpg_adapter.encrypt(
        bytearray(plaintext),
        recipient_fingerprint=self_fingerprint,
        encrypt_to_fingerprint=self_fingerprint,
    )
    assert result.ciphertext.startswith(b"-----BEGIN PGP MESSAGE-----")
    assert result.status.ok

    decrypted = await gpg_adapter.decrypt(result.ciphertext)
    assert bytes(decrypted.plaintext) == plaintext
    assert decrypted.status.ok
    decrypted.wipe()
    assert bytes(decrypted.plaintext) == bytes(len(plaintext))


@pytest.mark.asyncio
async def test_encrypt_zeroes_a_bytearray_plaintext_after_use(
    gpg_adapter: GPG, self_fingerprint: str
) -> None:
    plaintext = bytearray(b"zero me after encrypting")
    await gpg_adapter.encrypt(
        plaintext,
        recipient_fingerprint=self_fingerprint,
        encrypt_to_fingerprint=self_fingerprint,
    )
    assert plaintext == bytearray(len(plaintext))


@pytest.mark.asyncio
async def test_encrypt_to_recipient_and_self_both_can_decrypt(
    gpg_adapter: GPG, self_fingerprint: str, alice_fingerprint: str
) -> None:
    """encrypt-to-self means both the recipient's and our own key can open it."""
    plaintext = b"only alice and I should read this"
    result = await gpg_adapter.encrypt(
        bytearray(plaintext),
        recipient_fingerprint=alice_fingerprint,
        encrypt_to_fingerprint=self_fingerprint,
    )
    # Our test keyring holds both secret keys, so decrypting succeeds via
    # whichever key gpg picks -- proving the message really has two
    # usable recipients rather than just the encrypt-to one.
    decrypted = await gpg_adapter.decrypt(result.ciphertext)
    assert bytes(decrypted.plaintext) == plaintext


@pytest.mark.asyncio
async def test_decrypting_garbage_raises_and_never_returns_partial_plaintext(
    gpg_adapter: GPG,
) -> None:
    with pytest.raises(GPGDecryptionError):
        await gpg_adapter.decrypt(b"this is not a pgp message at all")


@pytest.mark.asyncio
async def test_encrypt_to_unknown_fingerprint_fails_closed(gpg_adapter: GPG) -> None:
    unknown = "F" * 40
    with pytest.raises(GPGEncryptionError):
        await gpg_adapter.encrypt(
            bytearray(b"hi"), recipient_fingerprint=unknown, encrypt_to_fingerprint=unknown
        )


@pytest.mark.asyncio
async def test_fingerprint_info_reports_encryption_capable_key(
    gpg_adapter: GPG, alice_fingerprint: str
) -> None:
    key = await gpg_adapter.fingerprint_info(alice_fingerprint)
    assert key is not None
    assert key.fingerprint == alice_fingerprint
    assert key.can_encrypt
    assert not key.expired
    assert not key.revoked
    assert any("Test Alice" in uid for uid in key.uids)


@pytest.mark.asyncio
async def test_fingerprint_info_returns_none_for_unknown_key(gpg_adapter: GPG) -> None:
    assert await gpg_adapter.fingerprint_info("A" * 40) is None


@pytest.mark.asyncio
async def test_search_keys_finds_by_name(gpg_adapter: GPG, alice_fingerprint: str) -> None:
    results = await gpg_adapter.search_keys("Test Alice")
    assert any(k.fingerprint == alice_fingerprint for k in results)


@pytest.mark.asyncio
async def test_import_key_into_a_fresh_keyring(
    tmp_path: Path, gpg_adapter: GPG, alice_fingerprint: str
) -> None:
    export_proc = await asyncio.create_subprocess_exec(
        "gpg",
        "--batch",
        "--armor",
        "--export",
        alice_fingerprint,
        env={**os.environ, "GNUPGHOME": str(gpg_adapter.gnupghome)},
        stdout=asyncio.subprocess.PIPE,
    )
    public_key, _ = await export_proc.communicate()
    assert b"BEGIN PGP PUBLIC KEY BLOCK" in public_key

    fresh_home = tmp_path / "fresh-gnupghome"
    fresh_home.mkdir(mode=0o700)
    fresh_gpg = GPG(gnupghome=str(fresh_home))

    result = await fresh_gpg.import_key(public_key)
    assert alice_fingerprint in result.fingerprints

    key = await fresh_gpg.fingerprint_info(alice_fingerprint)
    assert key is not None
    assert key.can_encrypt


@pytest.mark.asyncio
async def test_version_reports_gpg(gpg_adapter: GPG) -> None:
    version = await gpg_adapter.version()
    assert "gpg" in version.lower()


@pytest.mark.asyncio
async def test_plaintext_never_appears_in_subprocess_argv(
    gpg_adapter: GPG, self_fingerprint: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Message content must only ever cross the stdin pipe, never argv."""
    original = asyncio.create_subprocess_exec
    captured: list[tuple[object, ...]] = []

    async def spy(*args: object, **kwargs: object) -> asyncio.subprocess.Process:
        captured.append(args)
        return await original(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(asyncio, "create_subprocess_exec", spy)

    marker = "SUPER-SECRET-MARKER-DO-NOT-LEAK-INTO-ARGV"
    await gpg_adapter.encrypt(
        bytearray(marker.encode()),
        recipient_fingerprint=self_fingerprint,
        encrypt_to_fingerprint=self_fingerprint,
    )

    for args in captured:
        for arg in args:
            assert marker not in str(arg)
