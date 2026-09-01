"""Parsing for signal-cli JSON-RPC ``receive`` notifications.

Handles both ordinary incoming ``dataMessage`` envelopes and
``syncMessage``/``sentMessage`` envelopes -- the latter are how a
linked signal-cli account is told about messages *you* sent from
another device (or from ``sgpg`` itself), so your own sent messages
show up in the conversation too.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class SignalContact:
    number: str | None
    uuid: str | None
    name: str | None


def parse_contact(raw: dict[str, Any]) -> SignalContact:
    """Parse one entry from a ``listContacts`` response.

    signal-cli's exact JSON field names for contact display names have
    shifted across versions (``name``, ``profileName``, separate
    ``givenName``/``familyName``); this checks all of them so a contact
    with a name still shows one instead of "(no name)".
    """
    given = raw.get("givenName")
    family = raw.get("familyName")
    given_family = " ".join(p for p in (given, family) if p) or None
    name = raw.get("name") or raw.get("profileName") or given_family
    return SignalContact(number=raw.get("number"), uuid=raw.get("uuid"), name=name)


@dataclass(frozen=True, slots=True)
class IncomingMessage:
    account: str | None
    source_uuid: str | None
    source_number: str | None
    source_name: str | None
    destination_uuid: str | None
    destination_number: str | None
    timestamp: int | None
    body: str | None
    is_sync_sent: bool


def _from_data_message(envelope: dict[str, Any], account: str | None) -> IncomingMessage | None:
    data_message = envelope.get("dataMessage")
    if not isinstance(data_message, dict):
        return None
    body = data_message.get("message")
    if body is None:
        return None
    return IncomingMessage(
        account=account,
        source_uuid=envelope.get("sourceUuid"),
        source_number=envelope.get("sourceNumber"),
        source_name=envelope.get("sourceName"),
        destination_uuid=None,
        destination_number=None,
        timestamp=data_message.get("timestamp", envelope.get("timestamp")),
        body=body,
        is_sync_sent=False,
    )


def _from_sync_sent_message(
    envelope: dict[str, Any], account: str | None
) -> IncomingMessage | None:
    sync_message = envelope.get("syncMessage")
    if not isinstance(sync_message, dict):
        return None
    sent = sync_message.get("sentMessage")
    if not isinstance(sent, dict):
        return None
    body = sent.get("message")
    if body is None:
        return None
    return IncomingMessage(
        account=account,
        source_uuid=envelope.get("sourceUuid"),
        source_number=envelope.get("sourceNumber"),
        source_name=envelope.get("sourceName"),
        destination_uuid=sent.get("destinationUuid"),
        destination_number=sent.get("destinationNumber"),
        timestamp=sent.get("timestamp", envelope.get("timestamp")),
        body=body,
        is_sync_sent=True,
    )


def parse_receive_notification(params: Any) -> IncomingMessage | None:
    """Parse a "receive" notification's params into an IncomingMessage.

    Returns None for notification shapes we don't render as messages
    (typing indicators, receipts, group metadata updates, etc.) rather
    than raising -- an unrecognized-but-harmless notification should
    never crash the receive loop.
    """
    if not isinstance(params, dict):
        return None
    envelope = params.get("envelope")
    if not isinstance(envelope, dict):
        return None
    account = params.get("account")

    return _from_data_message(envelope, account) or _from_sync_sent_message(envelope, account)
