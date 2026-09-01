"""The Textual chat application.

Message bubbles are rendered from ciphertext on demand: opening a
contact decrypts their last N messages into memory; switching away
clears the conversation widgets and wipes the decrypted buffers. There
is no local chat database of plaintext -- only sgpg.history's
metadata/ciphertext store, and SgpgApp.read() decrypts from that fresh
every time a conversation is opened.
"""

from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack
from pathlib import Path
from typing import ClassVar

from textual.app import App, ComposeResult
from textual.binding import BindingType
from textual.containers import Horizontal, Vertical
from textual.widgets import Footer, Header, Label, ListView

from sgpg.app import SgpgApp
from sgpg.contacts.store import ContactStore
from sgpg.crypto.gpg import GPG, zero
from sgpg.history import MetadataStore
from sgpg.signal.client import (
    DaemonStartTimeoutError,
    SignalCliNotFoundError,
    connect,
    daemon_session,
)
from sgpg.tui.composer import Composer
from sgpg.tui.contacts import ContactListItem, populate
from sgpg.tui.conversation import ConversationView

_CSS = """
Screen {
    layout: horizontal;
}
#sidebar {
    width: 24;
    border-right: solid $accent;
}
#main {
    layout: vertical;
    width: 1fr;
}
ConversationView {
    height: 1fr;
    padding: 1;
}
Composer {
    height: 5;
    border: solid $accent;
}
#status {
    height: 1;
    color: $text-muted;
    padding: 0 1;
}
.bubble {
    margin: 0 0 1 0;
    padding: 0 1;
    width: 100%;
}
.bubble-mine {
    text-align: right;
}
.bubble-theirs {
    text-align: left;
}
.bubble-system {
    color: $text-muted;
    text-style: italic;
}
"""


class SgpgTUI(App[None]):
    CSS = _CSS
    TITLE = "sgpg"
    BINDINGS: ClassVar[list[BindingType]] = [("ctrl+q", "quit", "Quit")]

    def __init__(
        self,
        *,
        gnupghome: str | None,
        contacts_path: Path,
        history_path: Path,
        socket_path: Path,
        account: str | None,
        auto_daemon: bool = True,
        initial_contact: str | None = None,
    ) -> None:
        super().__init__()
        self._socket_path = socket_path
        self._account = account
        self._auto_daemon = auto_daemon
        self._initial_contact = initial_contact
        self._gpg = GPG(gnupghome=gnupghome)
        self._contacts = ContactStore(contacts_path)
        self._history = MetadataStore(history_path)
        self._sgpg: SgpgApp | None = None
        self._exit_stack = AsyncExitStack()
        self._current_contact: str | None = None
        self._receive_task: asyncio.Task[None] | None = None

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal():
            with Vertical(id="sidebar"):
                yield ListView(id="contact-list")
            with Vertical(id="main"):
                yield ConversationView(id="conversation")
                yield Composer(id="composer")
                yield Label("", id="status")
        yield Footer()

    async def on_mount(self) -> None:
        populate(self.query_one("#contact-list", ListView), self._contacts.list_contacts())

        if self._auto_daemon:
            self._set_status("starting signal-cli daemon…")
            try:
                spawned = await self._exit_stack.enter_async_context(
                    daemon_session(self._socket_path, account=self._account)
                )
                if spawned:
                    self._set_status("started signal-cli daemon")
            except (SignalCliNotFoundError, DaemonStartTimeoutError) as exc:
                self._set_status(f"couldn't start signal-cli daemon ({exc}) -- read-only")

        try:
            signal = await self._exit_stack.enter_async_context(
                connect(self._socket_path, account=self._account)
            )
            self._sgpg = SgpgApp(
                gpg=self._gpg, contacts=self._contacts, history=self._history, signal=signal
            )
            self._receive_task = asyncio.create_task(self._receive_loop())
            self._set_status("🔐 connected to Signal daemon")
        except OSError as exc:
            self._sgpg = SgpgApp(gpg=self._gpg, contacts=self._contacts, history=self._history)
            self._set_status(f"Signal daemon unreachable ({exc}) -- read-only")

        if self._initial_contact:
            await self._open_contact(self._initial_contact)

    async def on_unmount(self) -> None:
        if self._receive_task is not None:
            self._receive_task.cancel()
        # Reverse of entry order: closes the RPC connection before
        # stopping the daemon we might own, so we never kill the daemon
        # out from under a still-open client.
        await self._exit_stack.aclose()

    def _set_status(self, text: str) -> None:
        self.query_one("#status", Label).update(text)

    async def _receive_loop(self) -> None:
        if self._sgpg is None or self._sgpg.signal is None:
            return
        async for message in self._sgpg.signal.messages():
            contact_name = self._sgpg.record_incoming(message)
            if contact_name and contact_name == self._current_contact:
                await self._render_contact(contact_name)

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if isinstance(event.item, ContactListItem):
            self.run_worker(self._open_contact(event.item.contact_name))

    async def _open_contact(self, name: str) -> None:
        self._current_contact = name
        self.sub_title = name
        await self._render_contact(name)

    async def _render_contact(self, name: str) -> None:
        if self._sgpg is None:
            return
        conversation = self.query_one("#conversation", ConversationView)
        conversation.clear_conversation()
        rendered = await self._sgpg.read(name, limit=20)
        try:
            for msg in rendered:
                if msg.decrypted is not None:
                    text = msg.decrypted.plaintext.decode("utf-8", errors="replace")
                    badge = "🔐"
                    sig = msg.decrypted.status.signature
                    if sig is not None:
                        badge += " ✓ signed" if sig.valid else " ✗ bad signature"
                    who = "You" if msg.direction == "outgoing" else name
                    conversation.add_bubble(
                        who=who, text=text, mine=msg.direction == "outgoing", badge=badge
                    )
                else:
                    conversation.add_system(f"<{msg.error or 'undecryptable message'}>")
        finally:
            for msg in rendered:
                if msg.decrypted is not None:
                    msg.decrypted.wipe()

    def on_composer_send_requested(self, event: Composer.SendRequested) -> None:
        self.run_worker(self._send_current())

    async def _send_current(self) -> None:
        if self._sgpg is None or self._current_contact is None:
            self._set_status("no contact selected")
            return
        composer = self.query_one("#composer", Composer)
        text = composer.take_text()
        if not text.strip():
            return

        plaintext = bytearray(text.encode("utf-8"))
        try:
            await self._sgpg.send(self._current_contact, plaintext)
        except Exception as exc:
            self._set_status(f"send failed: {exc}")
            return
        finally:
            zero(plaintext)
        await self._render_contact(self._current_contact)


def run_tui(
    *,
    gnupghome: str | None,
    contacts_path: Path,
    history_path: Path,
    socket_path: Path,
    account: str | None,
    auto_daemon: bool = True,
    initial_contact: str | None = None,
) -> None:
    SgpgTUI(
        gnupghome=gnupghome,
        contacts_path=contacts_path,
        history_path=history_path,
        socket_path=socket_path,
        account=account,
        auto_daemon=auto_daemon,
        initial_contact=initial_contact,
    ).run()
