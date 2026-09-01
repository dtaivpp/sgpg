"""Parser for GnuPG's machine-readable ``--status-fd`` protocol.

We never infer success/failure from stderr text or exit codes alone;
GnuPG's status protocol is the documented, stable interface for that.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class StatusEvent:
    keyword: str
    args: tuple[str, ...]


def parse_status(raw: bytes) -> list[StatusEvent]:
    """Parse raw ``--status-fd`` output into structured events."""
    events: list[StatusEvent] = []
    for raw_line in raw.decode("utf-8", errors="replace").splitlines():
        stripped = raw_line.strip()
        if not stripped.startswith("[GNUPG:] "):
            continue
        keyword, *args = stripped[len("[GNUPG:] ") :].split(" ")
        events.append(StatusEvent(keyword=keyword, args=tuple(args)))
    return events


@dataclass(frozen=True, slots=True)
class SignatureStatus:
    valid: bool
    fingerprint: str | None
    signer_uid: str | None


@dataclass(frozen=True, slots=True)
class DecryptionStatus:
    ok: bool
    encrypted_to_fingerprints: tuple[str, ...]
    decryption_key_fingerprint: str | None
    smartcard_hint: bool
    signature: SignatureStatus | None
    failure_reason: str | None


@dataclass(frozen=True, slots=True)
class EncryptionStatus:
    ok: bool
    failure_reason: str | None


def interpret_decryption(events: list[StatusEvent]) -> DecryptionStatus:
    ok = False
    encrypted_to: list[str] = []
    decryption_key_fpr: str | None = None
    smartcard_hint = False
    signature: SignatureStatus | None = None
    failure_reason: str | None = None
    pending_sig_fpr: str | None = None

    for ev in events:
        match ev.keyword:
            case "DECRYPTION_OKAY":
                ok = True
            case "ENC_TO" if ev.args:
                encrypted_to.append(ev.args[0])
            case "DECRYPTION_KEY" if ev.args:
                decryption_key_fpr = ev.args[1] if len(ev.args) > 1 else ev.args[0]
            case "CARDCTRL" | "SC_OP_SUCCESS":
                smartcard_hint = True
            case "VALIDSIG" if ev.args:
                pending_sig_fpr = ev.args[0]
            case "GOODSIG":
                signature = SignatureStatus(
                    valid=True,
                    fingerprint=pending_sig_fpr,
                    signer_uid=" ".join(ev.args[1:]) if len(ev.args) > 1 else None,
                )
            case "BADSIG" | "ERRSIG" | "EXPSIG" | "EXPKEYSIG" | "REVKEYSIG":
                signature = SignatureStatus(
                    valid=False,
                    fingerprint=ev.args[0] if ev.args else pending_sig_fpr,
                    signer_uid=" ".join(ev.args[1:]) if len(ev.args) > 1 else None,
                )
            case "DECRYPTION_FAILED" | "NODATA":
                failure_reason = ev.keyword
            case "NO_SECKEY":
                failure_reason = f"no matching secret key: {ev.args[0] if ev.args else 'unknown'}"

    return DecryptionStatus(
        ok=ok,
        encrypted_to_fingerprints=tuple(encrypted_to),
        decryption_key_fingerprint=decryption_key_fpr,
        smartcard_hint=smartcard_hint,
        signature=signature,
        failure_reason=None if ok else (failure_reason or "decryption did not complete"),
    )


def interpret_encryption(events: list[StatusEvent]) -> EncryptionStatus:
    ok = False
    failure_reason: str | None = None
    for ev in events:
        match ev.keyword:
            case "END_ENCRYPTION":
                ok = True
            case "INV_RECP" | "NO_RECP":
                failure_reason = (
                    f"invalid recipient ({' '.join(ev.args)})" if ev.args else "invalid recipient"
                )
            case "FAILURE":
                failure_reason = " ".join(ev.args) if ev.args else "gpg reported failure"

    return EncryptionStatus(
        ok=ok,
        failure_reason=None if ok else (failure_reason or "encryption did not complete"),
    )
