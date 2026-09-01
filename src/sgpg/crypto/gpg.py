"""Disciplined subprocess adapter around the system ``gpg`` binary.

This module is **not** a cryptographic implementation. Every operation
here shells out to GnuPG. Rules enforced throughout:

* Plaintext and ciphertext are only ever exchanged with ``gpg`` over
  pipes (stdin/stdout) -- never via argv, never via temp files.
* ``argv`` never contains message content, only flags and fingerprints.
* We never invoke a shell (``shell=True`` is never used).
* We never set ``--trust-model always`` -- GnuPG's own trust machinery
  (Web of Trust / TOFU) stays in control of whether a key is usable.
* Success/failure is decided from GnuPG's ``--status-fd`` protocol,
  never from stderr text or exit codes alone.
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sgpg.crypto.status import (
    DecryptionStatus,
    EncryptionStatus,
    StatusEvent,
    interpret_decryption,
    interpret_encryption,
    parse_status,
)

_FINGERPRINT_RE = re.compile(r"^[0-9A-F]{40}([0-9A-F]{24})?$")


class GPGError(Exception):
    """Base class for all GPG adapter errors."""


class GPGNotFoundError(GPGError):
    """No ``gpg``/``gpg2`` binary was found on PATH."""


class InvalidFingerprintError(GPGError):
    """A string did not look like a full GPG fingerprint."""


class GPGEncryptionError(GPGError):
    """GPG refused or failed to encrypt (see ``status.failure_reason``)."""

    def __init__(self, status: EncryptionStatus, stderr: str) -> None:
        self.status = status
        self.stderr = stderr
        super().__init__(status.failure_reason or "encryption failed")


class GPGDecryptionError(GPGError):
    """GPG refused or failed to decrypt (see ``status.failure_reason``)."""

    def __init__(self, status: DecryptionStatus, stderr: str) -> None:
        self.status = status
        self.stderr = stderr
        super().__init__(status.failure_reason or "decryption failed")


class GPGImportError(GPGError):
    """A key import produced zero or an unexpected number of keys."""


def normalize_fingerprint(raw: str) -> str:
    """Validate and normalize a fingerprint to bare uppercase hex.

    Raises ``InvalidFingerprintError`` rather than silently accepting a
    short key id -- short/long key ids are spoofable and must never be
    used as trust anchors in this application.
    """
    candidate = raw.strip().replace(" ", "").upper()
    if not _FINGERPRINT_RE.match(candidate):
        raise InvalidFingerprintError(
            f"{raw!r} is not a full GPG fingerprint (need 40 or 64 hex chars)"
        )
    return candidate


def zero(buf: bytearray) -> None:
    """Best-effort overwrite of a mutable buffer's contents in place.

    CPython gives no hard guarantee that no other copy exists (interning,
    buffering, GC moves), but this removes the buffer we control as soon
    as it is no longer needed.
    """
    for i in range(len(buf)):
        buf[i] = 0


def find_gpg_binary() -> str:
    for name in ("gpg", "gpg2"):
        path = shutil.which(name)
        if path:
            return path
    raise GPGNotFoundError("no 'gpg' or 'gpg2' binary found on PATH")


def _unescape_colon_field(value: str) -> str:
    return re.sub(r"%([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), value)


def _parse_epoch(value: str) -> datetime | None:
    if not value or not value.isdigit():
        return None
    return datetime.fromtimestamp(int(value), tz=UTC)


@dataclass(frozen=True, slots=True)
class KeyInfo:
    fingerprint: str
    uids: tuple[str, ...]
    can_encrypt: bool
    can_sign: bool
    revoked: bool
    expired: bool
    expiry: datetime | None
    has_secret_key: bool = False


# Field indices in gpg --with-colons --fixed-list-mode records. See
# doc/DETAILS in the GnuPG source for the full field layout.
_COLON_VALIDITY_FIELD = 1
_COLON_EXPIRY_FIELD = 6
_COLON_UID_FIELD = 9
_COLON_FINGERPRINT_FIELD = 9
_COLON_CAPABILITIES_FIELD = 11


def _field(fields: list[str], index: int) -> str:
    return fields[index] if len(fields) > index else ""


@dataclass(slots=True)
class _PendingKey:
    fingerprint: str | None = None
    uids: list[str] = field(default_factory=list)
    can_encrypt: bool = False
    can_sign: bool = False
    revoked: bool = False
    expired: bool = False
    expiry: datetime | None = None


def _parse_colon_keys(output: str, *, has_secret: bool = False) -> list[KeyInfo]:
    keys: list[KeyInfo] = []
    current: _PendingKey | None = None

    def finalize() -> None:
        if current is None or not current.fingerprint:
            return
        keys.append(
            KeyInfo(
                fingerprint=current.fingerprint,
                uids=tuple(current.uids),
                can_encrypt=current.can_encrypt,
                can_sign=current.can_sign,
                revoked=current.revoked,
                expired=current.expired,
                expiry=current.expiry,
                has_secret_key=has_secret,
            )
        )

    for line in output.splitlines():
        fields = line.split(":")
        if not fields:
            continue
        rtype = fields[0]
        if rtype in ("pub", "sec"):
            finalize()
            validity = _field(fields, _COLON_VALIDITY_FIELD)
            caps = _field(fields, _COLON_CAPABILITIES_FIELD)
            current = _PendingKey(
                can_encrypt="e" in caps,
                can_sign="s" in caps,
                revoked=validity == "r",
                expired=validity == "e",
                expiry=_parse_epoch(_field(fields, _COLON_EXPIRY_FIELD)),
            )
        elif rtype == "fpr" and current is not None and not current.fingerprint:
            current.fingerprint = _field(fields, _COLON_FINGERPRINT_FIELD) or None
        elif rtype == "uid" and current is not None:
            uid = _field(fields, _COLON_UID_FIELD)
            if uid:
                current.uids.append(_unescape_colon_field(uid))
            if _field(fields, _COLON_VALIDITY_FIELD) == "r":
                current.revoked = True
        elif rtype in ("sub", "ssb") and current is not None:
            caps = _field(fields, _COLON_CAPABILITIES_FIELD)
            if "e" in caps:
                current.can_encrypt = True
            if "s" in caps:
                current.can_sign = True
    finalize()
    return keys


@dataclass(frozen=True, slots=True)
class EncryptResult:
    ciphertext: bytes
    status: EncryptionStatus


@dataclass(slots=True)
class DecryptResult:
    plaintext: bytearray
    status: DecryptionStatus

    def wipe(self) -> None:
        zero(self.plaintext)


@dataclass(frozen=True, slots=True)
class ImportResult:
    fingerprints: tuple[str, ...]


class GPG:
    """Async adapter around the system GPG binary."""

    def __init__(self, binary: str | None = None, *, gnupghome: str | None = None) -> None:
        self._binary = binary or find_gpg_binary()
        self._gnupghome = gnupghome

    @property
    def binary_path(self) -> str:
        return self._binary

    @property
    def gnupghome(self) -> str | None:
        return self._gnupghome

    def _base_env(self) -> dict[str, str]:
        env = dict(os.environ)
        if self._gnupghome:
            env["GNUPGHOME"] = self._gnupghome
        # Never let plaintext/secrets leak via env; we don't set anything
        # sensitive here, but we do make the intent explicit.
        return env

    async def _run(
        self, args: list[str], *, stdin_data: bytes | bytearray | None = None
    ) -> tuple[bytes, bytes, list[StatusEvent]]:
        """Run gpg with a status-fd pipe, feeding stdin_data over stdin.

        Never uses a shell. Never touches disk for I/O -- everything is
        pipes. Returns (stdout, stderr, status_events).
        """
        status_r, status_w = os.pipe()
        os.set_inheritable(status_w, True)
        full_args = [
            self._binary,
            "--batch",
            "--yes",
            "--no-tty",
            "--status-fd",
            str(status_w),
            *args,
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *full_args,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                pass_fds=(status_w,),
                env=self._base_env(),
            )
        finally:
            os.close(status_w)

        try:
            stdout_data, stderr_data = await proc.communicate(input=stdin_data)
        finally:
            loop = asyncio.get_running_loop()
            status_data = await loop.run_in_executor(None, _read_all_and_close, status_r)

        return stdout_data, stderr_data, parse_status(status_data)

    async def encrypt(
        self,
        plaintext: bytes | bytearray,
        *,
        recipient_fingerprint: str,
        encrypt_to_fingerprint: str,
        sign: bool = False,
        signer_fingerprint: str | None = None,
    ) -> EncryptResult:
        """Encrypt bytes to a recipient, always also encrypting to self.

        Never sets --trust-model always: if the recipient key is not
        sufficiently trusted GnuPG will refuse, and that refusal is
        surfaced as GPGEncryptionError rather than silently bypassed.
        """
        recipient = normalize_fingerprint(recipient_fingerprint)
        encrypt_to = normalize_fingerprint(encrypt_to_fingerprint)

        args = [
            "--armor",
            "--recipient",
            recipient,
            "--encrypt-to",
            encrypt_to,
        ]
        if sign:
            args.append("--sign")
            if signer_fingerprint:
                args += ["--local-user", normalize_fingerprint(signer_fingerprint)]
        args.append("--encrypt")

        try:
            stdout_data, stderr_data, events = await self._run(args, stdin_data=plaintext)
        finally:
            if isinstance(plaintext, bytearray):
                zero(plaintext)

        status = interpret_encryption(events)
        if not status.ok:
            raise GPGEncryptionError(status, stderr_data.decode("utf-8", errors="replace"))
        return EncryptResult(ciphertext=stdout_data, status=status)

    async def decrypt(self, ciphertext: bytes | bytearray) -> DecryptResult:
        """Decrypt an armored (or binary) message, returning a wipeable buffer."""
        stdout_data, stderr_data, events = await self._run(["--decrypt"], stdin_data=ciphertext)
        status = interpret_decryption(events)
        if not status.ok:
            # Never leak partial plaintext on a failed/ambiguous decrypt.
            raise GPGDecryptionError(status, stderr_data.decode("utf-8", errors="replace"))
        return DecryptResult(plaintext=bytearray(stdout_data), status=status)

    async def fingerprint_info(self, fingerprint: str) -> KeyInfo | None:
        fpr = normalize_fingerprint(fingerprint)
        stdout_data, _stderr, _events = await self._run(
            ["--with-colons", "--fixed-list-mode", "--fingerprint", "--list-keys", fpr]
        )
        keys = _parse_colon_keys(stdout_data.decode("utf-8", errors="replace"))
        for key in keys:
            if key.fingerprint == fpr:
                return key
        return None

    async def search_keys(self, query: str) -> list[KeyInfo]:
        """Search the local keyring (never a keyserver) for a query string."""
        stdout_data, _stderr, _events = await self._run(
            ["--with-colons", "--fixed-list-mode", "--fingerprint", "--list-keys", "--", query]
        )
        return _parse_colon_keys(stdout_data.decode("utf-8", errors="replace"))

    async def list_secret_key_fingerprints(self) -> tuple[str, ...]:
        stdout_data, _stderr, _events = await self._run(
            ["--with-colons", "--fixed-list-mode", "--fingerprint", "--list-secret-keys"]
        )
        keys = _parse_colon_keys(stdout_data.decode("utf-8", errors="replace"), has_secret=True)
        return tuple(k.fingerprint for k in keys)

    async def import_key(self, key_data: bytes) -> ImportResult:
        """Import ASCII-armored or binary key material via stdin (never a file path)."""
        _stdout, stderr_data, events = await self._run(["--import"], stdin_data=key_data)
        fingerprints = tuple(
            ev.args[1] for ev in events if ev.keyword == "IMPORT_OK" and len(ev.args) > 1
        )
        if not fingerprints:
            raise GPGImportError(
                "no keys imported: " + stderr_data.decode("utf-8", errors="replace").strip()
            )
        return ImportResult(fingerprints=fingerprints)

    async def version(self) -> str:
        stdout_data, _stderr, _events = await self._run(["--version"])
        first_line = stdout_data.decode("utf-8", errors="replace").splitlines()[0]
        return first_line


def _read_all_and_close(fd: int) -> bytes:
    try:
        with os.fdopen(fd, "rb") as f:
            return f.read()
    except OSError:
        return b""
