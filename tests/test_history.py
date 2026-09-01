from __future__ import annotations

import stat
from pathlib import Path

from sgpg.history import MetadataStore


def test_record_and_recent_messages_round_trip(tmp_history_path: Path) -> None:
    store = MetadataStore(tmp_history_path)
    store.record_message(
        "alice",
        direction="incoming",
        signal_timestamp=100,
        is_sgpg=True,
        envelope_kind="SGPG",
        ciphertext_armored="-----BEGIN PGP MESSAGE-----\nA\n-----END PGP MESSAGE-----",
    )
    store.record_message(
        "alice",
        direction="outgoing",
        signal_timestamp=200,
        is_sgpg=True,
        envelope_kind="SGPG",
        ciphertext_armored="-----BEGIN PGP MESSAGE-----\nB\n-----END PGP MESSAGE-----",
    )

    recent = store.recent_messages("alice", limit=20)
    assert [m.signal_timestamp for m in recent] == [100, 200]
    assert recent[0].direction == "incoming"
    assert recent[1].direction == "outgoing"
    assert recent[0].ciphertext_armored is not None


def test_metadata_db_written_with_owner_only_permissions(tmp_history_path: Path) -> None:
    MetadataStore(tmp_history_path)
    mode = stat.S_IMODE(tmp_history_path.stat().st_mode)
    assert mode == 0o600


def test_no_body_or_plaintext_column_exists(tmp_history_path: Path) -> None:
    store = MetadataStore(tmp_history_path)
    with store._connect() as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(messages)")}
    assert "body" not in columns
    assert "plaintext" not in columns


def test_last_seen_tracks_only_incoming_messages(tmp_history_path: Path) -> None:
    store = MetadataStore(tmp_history_path)
    store.record_message(
        "alice", direction="outgoing", signal_timestamp=500, is_sgpg=True, envelope_kind="SGPG"
    )
    assert store.last_seen("alice") is None

    store.record_message(
        "alice", direction="incoming", signal_timestamp=600, is_sgpg=True, envelope_kind="SGPG"
    )
    assert store.last_seen("alice") == 600


def test_inbox_orders_by_most_recent_first(tmp_history_path: Path) -> None:
    store = MetadataStore(tmp_history_path)
    store.record_message(
        "alice", direction="incoming", signal_timestamp=100, is_sgpg=True, envelope_kind="SGPG"
    )
    store.record_message(
        "bob", direction="incoming", signal_timestamp=300, is_sgpg=True, envelope_kind="SGPG"
    )

    inbox = store.inbox()
    assert inbox[0][0] == "bob"
    assert inbox[1][0] == "alice"


def test_ordinary_signal_messages_never_store_ciphertext(tmp_history_path: Path) -> None:
    store = MetadataStore(tmp_history_path)
    store.record_message(
        "alice",
        direction="incoming",
        signal_timestamp=100,
        is_sgpg=False,
        envelope_kind="ORDINARY",
        ciphertext_armored=None,
    )
    recent = store.recent_messages("alice")
    assert recent[0].ciphertext_armored is None


def test_recording_the_same_message_twice_is_idempotent(tmp_history_path: Path) -> None:
    store = MetadataStore(tmp_history_path)
    for _ in range(2):
        store.record_message(
            "alice", direction="incoming", signal_timestamp=100, is_sgpg=True, envelope_kind="SGPG"
        )
    assert len(store.recent_messages("alice")) == 1
