"""Headless Textual smoke tests.

Runs the real chat UI against the isolated test GnuPG keyring, with no
signal-cli daemon available -- exercising the "read-only, daemon
unreachable" path that a real user with no daemon running would hit.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sgpg.contacts.store import ContactStore
from sgpg.crypto.gpg import GPG
from sgpg.history import MetadataStore
from sgpg.tui.app import SgpgTUI
from sgpg.tui.composer import Composer
from sgpg.tui.contacts import ContactListItem
from sgpg.tui.conversation import ConversationView


@pytest.mark.asyncio
async def test_app_mounts_without_a_daemon_and_lists_contacts(
    gnupg_home: Path,
    tmp_contacts_path: Path,
    tmp_history_path: Path,
    tmp_path: Path,
    alice_fingerprint: str,
) -> None:
    contacts = ContactStore(tmp_contacts_path)
    contacts.add_contact("alice", signal_number="+15551234567", gpg_fingerprint=alice_fingerprint)
    contacts.save()

    app = SgpgTUI(
        gnupghome=str(gnupg_home),
        contacts_path=tmp_contacts_path,
        history_path=tmp_history_path,
        socket_path=tmp_path / "no-such.sock",
        account=None,
        # Never spawn a real signal-cli daemon subprocess in tests -- see
        # test_cli.py's cli_env fixture for the same reasoning.
        auto_daemon=False,
    )
    async with app.run_test() as pilot:
        await pilot.pause()
        items = app.query(ContactListItem)
        assert [item.contact_name for item in items] == ["alice"]
        status = app.query_one("#status")
        assert "unreachable" in str(status.content)  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_opening_a_contact_renders_decrypted_history(
    gnupg_home: Path,
    tmp_contacts_path: Path,
    tmp_history_path: Path,
    tmp_path: Path,
    self_fingerprint: str,
    alice_fingerprint: str,
    gpg_adapter: GPG,
) -> None:
    contacts = ContactStore(tmp_contacts_path)
    contacts.set_identity(self_fingerprint)
    contacts.add_contact("alice", signal_number="+15551234567", gpg_fingerprint=alice_fingerprint)
    contacts.save()

    encrypted = await gpg_adapter.encrypt(
        bytearray(b"hello from the test suite"),
        recipient_fingerprint=self_fingerprint,
        encrypt_to_fingerprint=self_fingerprint,
    )
    history = MetadataStore(tmp_history_path)
    history.record_message(
        "alice",
        direction="incoming",
        signal_timestamp=1000,
        is_sgpg=True,
        envelope_kind="SGPG",
        ciphertext_armored=encrypted.ciphertext.decode("ascii"),
    )

    app = SgpgTUI(
        gnupghome=str(gnupg_home),
        contacts_path=tmp_contacts_path,
        history_path=tmp_history_path,
        socket_path=tmp_path / "no-such.sock",
        account=None,
        auto_daemon=False,
        initial_contact="alice",
    )
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.pause()
        conversation = app.query_one(ConversationView)
        bubbles = conversation.query(".bubble")
        assert len(bubbles) == 1
        assert "hello from the test suite" in str(bubbles[0].content)  # type: ignore[attr-defined]

        composer = app.query_one(Composer)
        assert composer is not None
