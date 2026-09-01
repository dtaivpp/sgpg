"""Turns contact-store entries into GPG-validated, ready-to-use keys.

The fingerprint stored for a contact is only ever a pointer into the
keyring. This resolver re-validates it against the live keyring on
every use rather than caching key metadata, so an expired or revoked
key is caught immediately instead of silently persisting stale trust.
"""

from __future__ import annotations

from dataclasses import dataclass

from sgpg.contacts.store import Contact, ContactStore
from sgpg.crypto.gpg import GPG, KeyInfo


class UnresolvedContactError(Exception):
    pass


class UnusableKeyError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class ResolvedContact:
    contact: Contact
    key: KeyInfo


class ContactResolver:
    def __init__(self, store: ContactStore, gpg: GPG) -> None:
        self._store = store
        self._gpg = gpg

    async def search_candidate_keys(self, query: str) -> list[KeyInfo]:
        """Search the local keyring only -- never a keyserver."""
        return await self._gpg.search_keys(query)

    async def resolve(self, name: str) -> ResolvedContact:
        contact = self._store.get_contact(name)
        if contact is None:
            raise UnresolvedContactError(f"no such contact: {name}")
        if not contact.gpg_fingerprint:
            raise UnresolvedContactError(f"contact {name!r} has no gpg fingerprint set")

        key = await self._gpg.fingerprint_info(contact.gpg_fingerprint)
        if key is None:
            raise UnusableKeyError(
                f"fingerprint {contact.gpg_fingerprint} for {name!r} is not in your keyring"
            )
        if key.revoked:
            raise UnusableKeyError(f"{name}'s key ({key.fingerprint}) has been revoked")
        if key.expired:
            raise UnusableKeyError(f"{name}'s key ({key.fingerprint}) has expired")
        if not key.can_encrypt:
            raise UnusableKeyError(f"{name}'s key ({key.fingerprint}) has no encryption subkey")
        return ResolvedContact(contact=contact, key=key)

    async def own_identity_key(self) -> KeyInfo:
        fingerprint = self._store.identity_fingerprint()
        if not fingerprint:
            raise UnresolvedContactError(
                "no identity gpg_fingerprint configured; run 'sgpg doctor'"
            )
        key = await self._gpg.fingerprint_info(fingerprint)
        if key is None:
            raise UnusableKeyError(f"identity fingerprint {fingerprint} not found in keyring")
        return key
