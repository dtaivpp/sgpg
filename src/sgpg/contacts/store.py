"""TOML-backed contact store.

Only ever persists: Signal UUID/number, a nickname, and a GPG
fingerprint. Never a copy of anyone's public key. The file is written
with 0600 permissions since it reveals which Signal identities map to
which real-world people, even though it holds no cryptographic secrets.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import tomlkit
from tomlkit import TOMLDocument

from sgpg.crypto.gpg import normalize_fingerprint

_NAME_RE = re.compile(r"^[a-z0-9_-]+$")
_E164_RE = re.compile(r"^\+[1-9]\d{6,14}$")


class ContactStoreError(Exception):
    """Base class for contact-store errors."""


class ContactNotFoundError(ContactStoreError):
    pass


class DuplicateContactError(ContactStoreError):
    pass


@dataclass(frozen=True, slots=True)
class Contact:
    name: str
    signal_uuid: str | None = None
    signal_number: str | None = None
    gpg_fingerprint: str | None = None


def _validate_name(name: str) -> str:
    normalized = name.strip().lower()
    if not _NAME_RE.match(normalized):
        raise ContactStoreError(
            f"contact name {name!r} must contain only lowercase letters, digits, '-' or '_'"
        )
    return normalized


def _validate_phone_number(number: str) -> str:
    normalized = number.strip()
    if not _E164_RE.match(normalized):
        raise ContactStoreError(
            f"{number!r} doesn't look like an E.164 phone number (e.g. +15551234567)"
        )
    return normalized


class ContactStore:
    """Maps Signal identities to GPG fingerprints, backed by a TOML file."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._doc: TOMLDocument = self._load_or_init()

    def _load_or_init(self) -> TOMLDocument:
        if self._path.exists():
            return tomlkit.parse(self._path.read_text(encoding="utf-8"))
        doc = tomlkit.document()
        doc["identity"] = tomlkit.table()
        doc["contacts"] = tomlkit.table(is_super_table=True)
        return doc

    def save(self) -> None:
        self._path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        tmp_path = self._path.with_name(self._path.name + ".tmp")
        tmp_path.write_text(tomlkit.dumps(self._doc), encoding="utf-8")
        tmp_path.chmod(0o600)
        tmp_path.replace(self._path)
        self._path.chmod(0o600)

    # -- identity ---------------------------------------------------------

    def identity_fingerprint(self) -> str | None:
        identity = self._doc.get("identity")
        if not identity:
            return None
        fpr = identity.get("gpg_fingerprint")
        return str(fpr) if fpr else None

    def set_identity(self, fingerprint: str) -> None:
        fpr = normalize_fingerprint(fingerprint)
        if "identity" not in self._doc:
            self._doc["identity"] = tomlkit.table()
        self._doc["identity"]["gpg_fingerprint"] = fpr

    def identity_account(self) -> str | None:
        identity = self._doc.get("identity")
        if not identity:
            return None
        account = identity.get("signal_account")
        return str(account) if account else None

    def set_identity_account(self, phone_number: str) -> None:
        number = _validate_phone_number(phone_number)
        if "identity" not in self._doc:
            self._doc["identity"] = tomlkit.table()
        self._doc["identity"]["signal_account"] = number

    # -- contacts -----------------------------------------------------------

    def _contacts_table(self) -> Any:
        if "contacts" not in self._doc:
            self._doc["contacts"] = tomlkit.table(is_super_table=True)
        return self._doc["contacts"]

    def list_contacts(self) -> list[Contact]:
        table = self._contacts_table()
        return [self._contact_from_row(name, row) for name, row in table.items()]

    def get_contact(self, name: str) -> Contact | None:
        normalized = _validate_name(name)
        row = self._contacts_table().get(normalized)
        if row is None:
            return None
        return self._contact_from_row(normalized, row)

    @staticmethod
    def _contact_from_row(name: str, row: Any) -> Contact:
        return Contact(
            name=name,
            signal_uuid=row.get("signal_uuid"),
            signal_number=row.get("signal_number"),
            gpg_fingerprint=row.get("gpg_fingerprint"),
        )

    def add_contact(
        self,
        name: str,
        *,
        signal_uuid: str | None = None,
        signal_number: str | None = None,
        gpg_fingerprint: str | None = None,
    ) -> Contact:
        normalized = _validate_name(name)
        table = self._contacts_table()
        if normalized in table:
            raise DuplicateContactError(f"contact {normalized!r} already exists")
        if not signal_uuid and not signal_number:
            raise ContactStoreError("a contact needs a signal_uuid or a signal_number")

        row = tomlkit.table()
        if signal_uuid:
            row["signal_uuid"] = signal_uuid
        if signal_number:
            row["signal_number"] = signal_number
        if gpg_fingerprint:
            row["gpg_fingerprint"] = normalize_fingerprint(gpg_fingerprint)
        table[normalized] = row
        return self._contact_from_row(normalized, row)

    def set_key(self, name: str, fingerprint: str) -> Contact:
        normalized = _validate_name(name)
        row = self._contacts_table().get(normalized)
        if row is None:
            raise ContactNotFoundError(f"no such contact: {normalized}")
        row["gpg_fingerprint"] = normalize_fingerprint(fingerprint)
        return self._contact_from_row(normalized, row)

    def resolve_by_signal_id(
        self, *, uuid: str | None = None, number: str | None = None
    ) -> Contact | None:
        for contact in self.list_contacts():
            if uuid and contact.signal_uuid == uuid:
                return contact
            if number and contact.signal_number == number:
                return contact
        return None
