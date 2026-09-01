from __future__ import annotations

import stat
from pathlib import Path

import pytest

from sgpg.contacts.store import (
    ContactNotFoundError,
    ContactStore,
    ContactStoreError,
    DuplicateContactError,
)

FPR_ALICE = "0123456789ABCDEF0123456789ABCDEF01234567"
FPR_BOB = "FEDCBA9876543210FEDCBA9876543210FEDCBA98"


def test_add_and_list_contact(tmp_contacts_path: Path) -> None:
    store = ContactStore(tmp_contacts_path)
    store.add_contact("alice", signal_number="+15551234567", gpg_fingerprint=FPR_ALICE)
    store.save()

    reloaded = ContactStore(tmp_contacts_path)
    contacts = reloaded.list_contacts()
    assert len(contacts) == 1
    assert contacts[0].name == "alice"
    assert contacts[0].signal_number == "+15551234567"
    assert contacts[0].gpg_fingerprint == FPR_ALICE


def test_contact_file_written_with_owner_only_permissions(tmp_contacts_path: Path) -> None:
    store = ContactStore(tmp_contacts_path)
    store.add_contact("alice", signal_number="+15551234567")
    store.save()

    mode = stat.S_IMODE(tmp_contacts_path.stat().st_mode)
    assert mode == 0o600


def test_duplicate_contact_rejected(tmp_contacts_path: Path) -> None:
    store = ContactStore(tmp_contacts_path)
    store.add_contact("alice", signal_number="+15551234567")
    with pytest.raises(DuplicateContactError):
        store.add_contact("alice", signal_number="+15559999999")


def test_contact_requires_a_signal_identity(tmp_contacts_path: Path) -> None:
    store = ContactStore(tmp_contacts_path)
    with pytest.raises(ContactStoreError):
        store.add_contact("alice")


def test_set_key_on_unknown_contact_raises(tmp_contacts_path: Path) -> None:
    store = ContactStore(tmp_contacts_path)
    with pytest.raises(ContactNotFoundError):
        store.set_key("ghost", FPR_ALICE)


def test_set_key_normalizes_and_validates_fingerprint(tmp_contacts_path: Path) -> None:
    store = ContactStore(tmp_contacts_path)
    store.add_contact("alice", signal_number="+15551234567")
    store.set_key("alice", FPR_ALICE.lower())
    assert store.get_contact("alice").gpg_fingerprint == FPR_ALICE  # type: ignore[union-attr]


def test_invalid_fingerprint_rejected(tmp_contacts_path: Path) -> None:
    store = ContactStore(tmp_contacts_path)
    store.add_contact("alice", signal_number="+15551234567")
    with pytest.raises(Exception, match="fingerprint"):
        store.set_key("alice", "not-a-fingerprint")


def test_resolve_by_signal_id(tmp_contacts_path: Path) -> None:
    store = ContactStore(tmp_contacts_path)
    store.add_contact("alice", signal_uuid="uuid-1", signal_number="+15551234567")
    store.add_contact("bob", signal_number="+15559999999", gpg_fingerprint=FPR_BOB)

    assert store.resolve_by_signal_id(uuid="uuid-1").name == "alice"  # type: ignore[union-attr]
    assert store.resolve_by_signal_id(number="+15559999999").name == "bob"  # type: ignore[union-attr]
    assert store.resolve_by_signal_id(number="+10000000000") is None


def test_contact_names_are_restricted_to_safe_characters(tmp_contacts_path: Path) -> None:
    store = ContactStore(tmp_contacts_path)
    with pytest.raises(ContactStoreError):
        store.add_contact("Alice Example!", signal_number="+15551234567")


def test_identity_fingerprint_round_trip(tmp_contacts_path: Path) -> None:
    store = ContactStore(tmp_contacts_path)
    assert store.identity_fingerprint() is None
    store.set_identity(FPR_ALICE)
    store.save()

    reloaded = ContactStore(tmp_contacts_path)
    assert reloaded.identity_fingerprint() == FPR_ALICE


def test_identity_account_round_trip(tmp_contacts_path: Path) -> None:
    store = ContactStore(tmp_contacts_path)
    assert store.identity_account() is None
    store.set_identity_account("+15551234567")
    store.save()

    reloaded = ContactStore(tmp_contacts_path)
    assert reloaded.identity_account() == "+15551234567"


@pytest.mark.parametrize(
    "bogus",
    ["5551234567", "not-a-number", "+1", "++15551234567", ""],
)
def test_identity_account_rejects_non_e164(tmp_contacts_path: Path, bogus: str) -> None:
    store = ContactStore(tmp_contacts_path)
    with pytest.raises(ContactStoreError):
        store.set_identity_account(bogus)


def test_contacts_toml_never_contains_a_public_key_block(tmp_contacts_path: Path) -> None:
    """Only fingerprints -- pointers into the keyring -- are ever persisted."""
    store = ContactStore(tmp_contacts_path)
    store.add_contact("alice", signal_number="+15551234567", gpg_fingerprint=FPR_ALICE)
    store.save()

    text = tmp_contacts_path.read_text(encoding="utf-8")
    assert "BEGIN PGP PUBLIC KEY BLOCK" not in text
