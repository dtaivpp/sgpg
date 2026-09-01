from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pytest

from sgpg.app import SgpgApp
from sgpg.contacts.store import ContactStore
from sgpg.crypto.gpg import GPG
from sgpg.history import MetadataStore
from sgpg.signal.messages import IncomingMessage


@dataclass
class _FakeSignal:
    sent: list[tuple[str, str]] = field(default_factory=list)

    async def send(self, recipient: str, message: str) -> None:
        self.sent.append((recipient, message))


@pytest.fixture
def app(
    gpg_adapter: GPG,
    tmp_contacts_path: Path,
    tmp_history_path: Path,
    self_fingerprint: str,
    alice_fingerprint: str,
) -> SgpgApp:
    contacts = ContactStore(tmp_contacts_path)
    contacts.set_identity(self_fingerprint)
    contacts.add_contact("alice", signal_number="+15551234567", gpg_fingerprint=alice_fingerprint)
    history = MetadataStore(tmp_history_path)
    return SgpgApp(gpg=gpg_adapter, contacts=contacts, history=history, signal=_FakeSignal())  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_send_encrypts_wraps_and_hands_off_to_signal(app: SgpgApp) -> None:
    plaintext = bytearray(b"the deploy finished, ship it")
    receipt = await app.send("alice", plaintext)

    assert receipt.contact_name == "alice"
    signal = app.signal
    assert isinstance(signal, _FakeSignal)
    assert len(signal.sent) == 1
    recipient, envelope = signal.sent[0]
    assert recipient == "+15551234567"
    assert envelope.startswith("SGPG/1\n-----BEGIN PGP MESSAGE-----")

    # Plaintext must be gone from the caller's buffer after sending.
    assert plaintext == bytearray(len(plaintext))


@pytest.mark.asyncio
async def test_send_and_then_read_round_trips_through_local_history(app: SgpgApp) -> None:
    await app.send("alice", bytearray(b"first message"))
    await app.send("alice", bytearray(b"second message"))

    rendered = await app.read("alice", limit=20)
    assert [m.decrypted.plaintext.decode() for m in rendered if m.decrypted] == [
        "first message",
        "second message",
    ]
    for msg in rendered:
        assert msg.decrypted is not None
        msg.decrypted.wipe()


@pytest.mark.asyncio
async def test_record_incoming_matches_known_contact_and_stores_ciphertext(
    app: SgpgApp,
) -> None:
    incoming = IncomingMessage(
        account="+15550000000",
        source_uuid=None,
        source_number="+15551234567",
        source_name="Alice",
        destination_uuid=None,
        destination_number=None,
        timestamp=1000,
        body="SGPG/1\n-----BEGIN PGP MESSAGE-----\nfakebody\n-----END PGP MESSAGE-----",
        is_sync_sent=False,
    )
    matched = app.record_incoming(incoming)
    assert matched == "alice"

    recent = app.history.recent_messages("alice")
    assert recent[0].is_sgpg
    assert recent[0].ciphertext_armored is not None


@pytest.mark.asyncio
async def test_record_incoming_ignores_unknown_senders(app: SgpgApp) -> None:
    incoming = IncomingMessage(
        account=None,
        source_uuid=None,
        source_number="+19995550000",  # not a known contact
        source_name=None,
        destination_uuid=None,
        destination_number=None,
        timestamp=1000,
        body="hello",
        is_sync_sent=False,
    )
    assert app.record_incoming(incoming) is None


@pytest.mark.asyncio
async def test_record_incoming_never_stores_ciphertext_for_ordinary_messages(
    app: SgpgApp,
) -> None:
    incoming = IncomingMessage(
        account=None,
        source_uuid=None,
        source_number="+15551234567",
        source_name="Alice",
        destination_uuid=None,
        destination_number=None,
        timestamp=2000,
        body="just saying hi, not encrypted",
        is_sync_sent=False,
    )
    app.record_incoming(incoming)
    recent = app.history.recent_messages("alice")
    assert not recent[0].is_sgpg
    assert recent[0].ciphertext_armored is None


@pytest.mark.asyncio
async def test_send_without_a_signal_client_raises(
    gpg_adapter: GPG, tmp_contacts_path: Path, tmp_history_path: Path, self_fingerprint: str
) -> None:
    contacts = ContactStore(tmp_contacts_path)
    contacts.set_identity(self_fingerprint)
    history = MetadataStore(tmp_history_path)
    offline_app = SgpgApp(gpg=gpg_adapter, contacts=contacts, history=history)

    with pytest.raises(RuntimeError, match="not connected"):
        await offline_app.send("alice", bytearray(b"hi"))
