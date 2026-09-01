"""SGPG/1 message envelope.

Version 1 contains almost nothing except the armored PGP message itself,
so future versions can add structure without inventing any crypto of
our own:

    SGPG/1
    -----BEGIN PGP MESSAGE-----
    ...
    -----END PGP MESSAGE-----

Classification is deliberately strict: a message is only ever treated as
SGPG if its *first line* is an exact ``SGPG/<n>`` marker. Ordinary Signal
messages -- including ones that happen to mention PGP -- must never be
fed into ``gpg --decrypt``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum, auto

SGPG_VERSION = 1

_VERSION_LINE_RE = re.compile(r"^SGPG/(\d+)\s*$")
_ARMOR_BEGIN = "-----BEGIN PGP MESSAGE-----"
_ARMOR_END = "-----END PGP MESSAGE-----"


class MessageKind(Enum):
    ORDINARY = auto()
    SGPG = auto()
    UNSUPPORTED_VERSION = auto()
    MALFORMED = auto()


@dataclass(frozen=True, slots=True)
class ClassifiedMessage:
    kind: MessageKind
    version: int | None
    armored_payload: str | None


def wrap(armored_message: str) -> str:
    """Wrap an ASCII-armored PGP message in the current SGPG envelope."""
    armored = armored_message.strip()
    if not armored.startswith(_ARMOR_BEGIN):
        raise ValueError("expected an ASCII-armored PGP message block")
    return f"SGPG/{SGPG_VERSION}\n{armored}\n"


def classify(text: str) -> ClassifiedMessage:
    """Classify an incoming Signal message body."""
    lines = text.splitlines()
    if not lines:
        return ClassifiedMessage(MessageKind.ORDINARY, None, None)

    match = _VERSION_LINE_RE.match(lines[0])
    if not match:
        return ClassifiedMessage(MessageKind.ORDINARY, None, None)

    version = int(match.group(1))
    if version != SGPG_VERSION:
        return ClassifiedMessage(MessageKind.UNSUPPORTED_VERSION, version, None)

    body = "\n".join(lines[1:]).strip()
    if body.startswith(_ARMOR_BEGIN) and body.endswith(_ARMOR_END):
        return ClassifiedMessage(MessageKind.SGPG, version, body)
    return ClassifiedMessage(MessageKind.MALFORMED, version, None)
