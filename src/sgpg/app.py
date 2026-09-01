"""Composition root: wires GPG, contacts, Signal, and history together.

Every important operation is exposed as a plain async method here so
that both the CLI (cli.py) and the Textual TUI (tui/) can be thin
presentation layers over the same tested primitives, rather than
duplicating business logic.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from sgpg.contacts.resolver import ContactResolver
from sgpg.contacts.store import ContactStore
from sgpg.crypto.gpg import GPG, DecryptResult, zero
from sgpg.history import MetadataStore
from sgpg.protocol.envelope import MessageKind, classify, wrap
from sgpg.signal.client import SignalClient
from sgpg.signal.messages import IncomingMessage


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


@dataclass(frozen=True, slots=True)
class SendReceipt:
    contact_name: str
    signal_timestamp: int
    signed: bool


@dataclass(frozen=True, slots=True)
class RenderedMessage:
    direction: str
    signal_timestamp: int
    decrypted: DecryptResult | None
    error: str | None


class SgpgApp:
    def __init__(
        self,
        *,
        gpg: GPG,
        contacts: ContactStore,
        history: MetadataStore,
        signal: SignalClient | None = None,
    ) -> None:
        self.gpg = gpg
        self.contacts = contacts
        self.signal = signal
        self.history = history
        self.resolver = ContactResolver(contacts, gpg)

    async def send(
        self, contact_name: str, plaintext: bytes | bytearray, *, sign: bool = False
    ) -> SendReceipt:
        """Encrypt to contact_name (and to self), then hand off to Signal.

        1. Resolve Alice -> Signal identity
        2. Resolve Alice -> GPG fingerprint
        3. Ask GPG whether the key is usable          (resolver.resolve)
        4. (caller already has plaintext)
        5-7. Pipe plaintext into GPG, encrypt-to Alice + self
        8. Pass armored ciphertext to signal-cli
        9. Destroy Python plaintext references         (gpg.encrypt zeroes it)
        """
        if self.signal is None:
            raise RuntimeError("not connected to a Signal daemon")

        resolved = await self.resolver.resolve(contact_name)
        own_key = await self.resolver.own_identity_key()

        recipient_id = resolved.contact.signal_uuid or resolved.contact.signal_number
        if not recipient_id:
            raise ValueError(f"contact {contact_name!r} has no signal_uuid or signal_number")

        try:
            result = await self.gpg.encrypt(
                plaintext,
                recipient_fingerprint=resolved.key.fingerprint,
                encrypt_to_fingerprint=own_key.fingerprint,
                sign=sign,
            )
        finally:
            # gpg.encrypt() already zeroes bytearray input; this is a
            # belt-and-suspenders no-op for bytes (which can't be zeroed)
            # and is here so the intent is visible at the call site.
            if isinstance(plaintext, bytearray):
                zero(plaintext)

        armored = result.ciphertext.decode("ascii")
        envelope = wrap(armored)
        await self.signal.send(recipient_id, envelope)

        timestamp = _now_ms()
        self.history.record_message(
            contact_name,
            direction="outgoing",
            signal_timestamp=timestamp,
            is_sgpg=True,
            envelope_kind="SGPG",
            ciphertext_armored=armored,
        )
        return SendReceipt(contact_name=contact_name, signal_timestamp=timestamp, signed=sign)

    def record_incoming(self, message: IncomingMessage) -> str | None:
        """Classify + persist metadata (and ciphertext, if SGPG) for an
        incoming or sync-sent message. Returns the matched contact name,
        or None if the sender/recipient isn't a known contact.
        """
        if message.body is None or message.timestamp is None:
            return None

        contact = self.contacts.resolve_by_signal_id(
            uuid=message.destination_uuid or message.source_uuid,
            number=message.destination_number or message.source_number,
        )
        if contact is None:
            return None

        classified = classify(message.body)
        is_sgpg = classified.kind is MessageKind.SGPG
        self.history.record_message(
            contact.name,
            direction="outgoing" if message.is_sync_sent else "incoming",
            signal_timestamp=message.timestamp,
            is_sgpg=is_sgpg,
            envelope_kind=classified.kind.name,
            ciphertext_armored=classified.armored_payload if is_sgpg else None,
        )
        return contact.name

    async def read(self, contact_name: str, limit: int = 20) -> list[RenderedMessage]:
        """Decrypt-last-N: pull stored SGPG ciphertext and decrypt it in
        memory for display. Plaintext is only ever handed back to the
        caller, never written here; the caller owns wiping it after use.
        """
        rendered: list[RenderedMessage] = []
        for meta in self.history.recent_messages(contact_name, limit=limit):
            if not meta.is_sgpg or meta.ciphertext_armored is None:
                rendered.append(
                    RenderedMessage(
                        direction=meta.direction,
                        signal_timestamp=meta.signal_timestamp,
                        decrypted=None,
                        error="not an SGPG-encrypted message",
                    )
                )
                continue
            try:
                result = await self.gpg.decrypt(meta.ciphertext_armored.encode("ascii"))
            except Exception as exc:
                rendered.append(
                    RenderedMessage(
                        direction=meta.direction,
                        signal_timestamp=meta.signal_timestamp,
                        decrypted=None,
                        error=str(exc),
                    )
                )
                continue
            rendered.append(
                RenderedMessage(
                    direction=meta.direction,
                    signal_timestamp=meta.signal_timestamp,
                    decrypted=result,
                    error=None,
                )
            )
        return rendered

    def inbox(self) -> list[tuple[str, int]]:
        return self.history.inbox()
