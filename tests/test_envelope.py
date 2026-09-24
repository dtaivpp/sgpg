from __future__ import annotations

import pytest

from sgpg.protocol.envelope import (
    MAX_ENVELOPE_LENGTH,
    MessageKind,
    MessageTooLargeError,
    classify,
    wrap,
)

ARMORED = "-----BEGIN PGP MESSAGE-----\n\nhQEMA...fake...\n-----END PGP MESSAGE-----"


def test_wrap_prefixes_version_marker() -> None:
    wrapped = wrap(ARMORED)
    assert wrapped.startswith("SGPG/1\n")
    assert "-----BEGIN PGP MESSAGE-----" in wrapped
    assert "-----END PGP MESSAGE-----" in wrapped


def test_wrap_rejects_non_armored_input() -> None:
    with pytest.raises(ValueError, match="armored"):
        wrap("just some text, not a pgp message")


def test_wrap_rejects_an_envelope_over_the_size_limit() -> None:
    """Truncating an armored PGP block corrupts its checksum/packet
    structure and makes it entirely undecryptable -- refuse to build
    an oversized envelope rather than risk that ever happening.
    """
    oversized_armor = (
        "-----BEGIN PGP MESSAGE-----\n\n" + ("A" * MAX_ENVELOPE_LENGTH) + "\n"
        "-----END PGP MESSAGE-----"
    )
    with pytest.raises(MessageTooLargeError) as exc_info:
        wrap(oversized_armor)
    assert exc_info.value.limit == MAX_ENVELOPE_LENGTH
    assert exc_info.value.length > MAX_ENVELOPE_LENGTH


def test_wrap_accepts_an_envelope_right_at_the_size_limit() -> None:
    armor_overhead = len(wrap("-----BEGIN PGP MESSAGE-----\n\n\n-----END PGP MESSAGE-----"))
    filler = "A" * (MAX_ENVELOPE_LENGTH - armor_overhead)
    armored = f"-----BEGIN PGP MESSAGE-----\n\n{filler}\n-----END PGP MESSAGE-----"
    wrapped = wrap(armored)
    assert len(wrapped) == MAX_ENVELOPE_LENGTH


def test_classify_round_trip() -> None:
    wrapped = wrap(ARMORED)
    classified = classify(wrapped)
    assert classified.kind is MessageKind.SGPG
    assert classified.version == 1
    assert classified.armored_payload is not None
    assert classified.armored_payload.startswith("-----BEGIN PGP MESSAGE-----")


@pytest.mark.parametrize(
    "text",
    [
        "hey, did you see the game last night?",
        "-----BEGIN PGP MESSAGE-----\nlooks encrypted but has no SGPG marker\n"
        "-----END PGP MESSAGE-----",
        "",
        "SGPG mentioned but not as the version line",
    ],
)
def test_ordinary_messages_are_never_classified_as_sgpg(text: str) -> None:
    """Ordinary Signal messages must never be fed into gpg --decrypt."""
    classified = classify(text)
    assert classified.kind is MessageKind.ORDINARY
    assert classified.armored_payload is None


def test_unsupported_future_version_is_flagged_not_decrypted() -> None:
    classified = classify("SGPG/2\nsome-future-shape\n")
    assert classified.kind is MessageKind.UNSUPPORTED_VERSION
    assert classified.version == 2
    assert classified.armored_payload is None


def test_malformed_sgpg_body_is_flagged_not_decrypted() -> None:
    classified = classify("SGPG/1\nthis is not an armored pgp message\n")
    assert classified.kind is MessageKind.MALFORMED
    assert classified.armored_payload is None


def test_truncated_armor_is_malformed() -> None:
    classified = classify("SGPG/1\n-----BEGIN PGP MESSAGE-----\nhQEMA...\n")
    assert classified.kind is MessageKind.MALFORMED
