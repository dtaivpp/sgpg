"""SQLite metadata + ciphertext store.

signal-cli's JSON-RPC surface has no history-replay method -- only a
live ``receive`` stream. So "decrypt the last N messages" (invariant:
ciphertext may be persisted; plaintext may not) is only possible if
this application keeps its own copy of the SGPG-armored ciphertext as
messages arrive/are sent, and decrypts on demand for display.

What is stored: which contact, direction, the Signal timestamp
(Signal's de facto message id), whether the message looked like an
SGPG envelope, and -- only for SGPG envelopes -- the armored ciphertext
itself. There is deliberately no *plaintext* column anywhere in this
schema, and non-SGPG (ordinary Signal) messages never get their body
stored at all, encrypted or not.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    contact_name TEXT NOT NULL,
    direction TEXT NOT NULL CHECK(direction IN ('incoming', 'outgoing')),
    signal_timestamp INTEGER NOT NULL,
    is_sgpg INTEGER NOT NULL,
    envelope_kind TEXT NOT NULL,
    ciphertext_armored TEXT,
    UNIQUE(contact_name, direction, signal_timestamp)
);

CREATE TABLE IF NOT EXISTS last_seen (
    contact_name TEXT PRIMARY KEY,
    signal_timestamp INTEGER NOT NULL
);
"""


@dataclass(frozen=True, slots=True)
class MessageMeta:
    contact_name: str
    direction: str
    signal_timestamp: int
    is_sgpg: bool
    envelope_kind: str
    ciphertext_armored: str | None


class MetadataStore:
    def __init__(self, path: Path) -> None:
        self._path = path
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
        path.chmod(0o600)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self._path)
        try:
            conn.execute("PRAGMA foreign_keys = ON")
            yield conn
            conn.commit()
        finally:
            conn.close()

    def record_message(
        self,
        contact_name: str,
        *,
        direction: str,
        signal_timestamp: int,
        is_sgpg: bool,
        envelope_kind: str,
        ciphertext_armored: str | None = None,
    ) -> None:
        if direction not in ("incoming", "outgoing"):
            raise ValueError(f"invalid direction: {direction!r}")
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO messages
                    (contact_name, direction, signal_timestamp, is_sgpg,
                     envelope_kind, ciphertext_armored)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    contact_name,
                    direction,
                    signal_timestamp,
                    int(is_sgpg),
                    envelope_kind,
                    ciphertext_armored,
                ),
            )
            if direction == "incoming":
                conn.execute(
                    """
                    INSERT INTO last_seen (contact_name, signal_timestamp)
                    VALUES (?, ?)
                    ON CONFLICT(contact_name) DO UPDATE SET
                        signal_timestamp = MAX(signal_timestamp, excluded.signal_timestamp)
                    """,
                    (contact_name, signal_timestamp),
                )

    def recent_messages(self, contact_name: str, limit: int = 20) -> list[MessageMeta]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT contact_name, direction, signal_timestamp, is_sgpg,
                       envelope_kind, ciphertext_armored
                FROM messages
                WHERE contact_name = ?
                ORDER BY signal_timestamp DESC
                LIMIT ?
                """,
                (contact_name, limit),
            ).fetchall()
        return [
            MessageMeta(
                contact_name=r[0],
                direction=r[1],
                signal_timestamp=r[2],
                is_sgpg=bool(r[3]),
                envelope_kind=r[4],
                ciphertext_armored=r[5],
            )
            for r in reversed(rows)
        ]

    def last_seen(self, contact_name: str) -> int | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT signal_timestamp FROM last_seen WHERE contact_name = ?",
                (contact_name,),
            ).fetchone()
        return int(row[0]) if row else None

    def inbox(self) -> list[tuple[str, int]]:
        """Contacts with at least one recorded message, newest first."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT contact_name, signal_timestamp "
                "FROM last_seen ORDER BY signal_timestamp DESC"
            ).fetchall()
        return [(r[0], int(r[1])) for r in rows]
