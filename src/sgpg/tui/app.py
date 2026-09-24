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
import contextlib
import logging
from collections.abc import Iterator
from contextlib import AsyncExitStack, contextmanager
from pathlib import Path
from typing import ClassVar

from textual.app import App, ComposeResult, SuspendNotSupported
from textual.binding import BindingType
from textual.containers import Horizontal, Vertical
from textual.widgets import Footer, Header, Label, ListView

from sgpg.app import SgpgApp
from sgpg.contacts.store import ContactStore
from sgpg.crypto import card as card_module
from sgpg.crypto.card import CardRelearnError, GPGConnectAgentNotFoundError
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
    BINDINGS: ClassVar[list[BindingType]] = [
        ("ctrl+q", "quit", "Quit"),
        ("ctrl+r", "retry_decrypt", "Retry decryption"),
    ]

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
            with contextlib.suppress(asyncio.CancelledError):
                await self._receive_task
        # Reverse of entry order: closes the RPC connection before
        # stopping the daemon we might own, so we never kill the daemon
        # out from under a still-open client. An exception here must
        # never escape on_unmount -- that would interrupt Textual's own
        # shutdown sequence and could leave the terminal in raw mode.
        try:
            await self._exit_stack.aclose()
        except Exception:
            logging.getLogger(__name__).warning("error while shutting down Signal connection")

    def _set_status(self, text: str) -> None:
        self.query_one("#status", Label).update(text)

    @contextmanager
    def _yield_terminal_to_gpg(self) -> Iterator[None]:
        """Hand the terminal to gpg-agent's pinentry for the duration.

        A card decrypt can pop a pinentry-curses PIN/touch prompt that
        draws directly on the controlling terminal -- the same terminal
        Textual is holding in raw/alt-screen mode. Without yielding it
        first, the two fight over the tty: the screen looks frozen until
        a resize forces Textual to repaint, and the PIN/touch prompt can
        be garbled badly enough that it never actually reaches the card,
        so decryption keeps failing even once the key is back in. This
        is the same App.suspend() trick Textual recommends for shelling
        out to $EDITOR. Falls back to running un-suspended (e.g. under
        the headless test driver, or a Textual driver that can't
        suspend) rather than failing the decrypt outright.
        """
        try:
            with self.suspend():
                yield
        except SuspendNotSupported:
            yield

    async def _receive_loop(self) -> None:
        if self._sgpg is None or self._sgpg.signal is None:
            return
        async for message in self._sgpg.signal.messages():
            contact_name = await self._sgpg.record_incoming(message)
            if contact_name and contact_name == self._current_contact:
                await self._render_contact(contact_name)

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if isinstance(event.item, ContactListItem):
            self.run_worker(self._open_contact(event.item.contact_name))

    async def _open_contact(self, name: str) -> None:
        self._current_contact = name
        self.sub_title = name
        await self._render_contact(name)

    async def _render_contact(self, name: str) -> int:
        """Re-decrypt and re-render `name`'s history from scratch.

        There is no cached plaintext or cached failure anywhere in this
        stack (see SgpgApp.read()), so simply calling this again -- via
        action_retry_decrypt, a new incoming message, or reopening the
        contact -- re-attempts decryption for every message, including
        ones that failed last time (e.g. because a smartcard reader was
        unplugged). Returns the number of messages that still failed.
        """
        if self._sgpg is None:
            return 0
        conversation = self.query_one("#conversation", ConversationView)
        conversation.clear_conversation()
        with self._yield_terminal_to_gpg():
            rendered = await self._sgpg.read(name, limit=20)
        still_failing = 0
        try:
            for msg in rendered:
                if msg.decrypted is not None:
                    text = msg.decrypted.plaintext.decode("utf-8", errors="replace")
                    # Only a genuine SGPG envelope was end-to-end
                    # encrypted (and possibly signed) by the sender --
                    # an ordinary message we encrypted at rest for our
                    # own safekeeping must never look the same as one.
                    badge = ""
                    if msg.is_sgpg:
                        badge = "🔐"
                        sig = msg.decrypted.status.signature
                        if sig is not None:
                            badge += " ✓ signed" if sig.valid else " ✗ bad signature"
                    who = "You" if msg.direction == "outgoing" else name
                    conversation.add_bubble(
                        who=who, text=text, mine=msg.direction == "outgoing", badge=badge
                    )
                else:
                    still_failing += 1
                    conversation.add_system(f"<{msg.error or 'undecryptable message'}>")
        finally:
            for msg in rendered:
                if msg.decrypted is not None:
                    msg.decrypted.wipe()
        return still_failing

    def action_retry_decrypt(self) -> None:
        if self._current_contact is None:
            self._set_status("no conversation open to retry")
            return
        # Dispatch to a worker rather than awaiting inline: key-bound
        # actions run on the App's single message-processing task, so a
        # slow gpg/scdaemon round trip (e.g. a card that hasn't been
        # relearned yet) would otherwise stall all key handling and
        # rendering until it returned. exclusive=True drops a prior
        # still-running retry if the user mashes the key again.
        self.run_worker(self._retry_decrypt(), group="retry-decrypt", exclusive=True)

    async def _retry_decrypt(self) -> None:
        contact_name = self._current_contact
        if contact_name is None:
            return
        # A YubiKey that was unplugged and replugged doesn't get noticed
        # by gpg-agent/scdaemon on its own -- it still believes no card
        # (or the old one) is present until told to relearn. Nudge it
        # before re-decrypting; this is the same SCD SERIALNO / SCD LEARN
        # sequence as `sgpg card learn`. Best-effort: a missing
        # gpg-connect-agent or a failed relearn shouldn't block the
        # decrypt retry itself, which will surface its own real error.
        self._set_status("checking smartcard…")
        try:
            await card_module.relearn_card()
        except (CardRelearnError, GPGConnectAgentNotFoundError) as exc:
            logging.getLogger(__name__).info("card relearn skipped: %s", exc)

        self._set_status("retrying decryption…")
        still_failing = await self._render_contact(contact_name)
        if still_failing:
            self._set_status(f"retried decryption -- {still_failing} message(s) still failing")
        else:
            self._set_status("retried decryption -- all messages decrypted")

    def on_composer_send_requested(self, event: Composer.SendRequested) -> None:
        self.run_worker(self._send_current())

    async def _send_current(self) -> None:
        if self._sgpg is None or self._current_contact is None:
            self._set_status("no contact selected")
            return
        composer = self.query_one("#composer", Composer)
        text = composer.text
        if not text.strip():
            return

        plaintext = bytearray(text.encode("utf-8"))
        try:
            await self._sgpg.send(self._current_contact, plaintext)
        except Exception as exc:
            # Leave the composer's text in place on failure (e.g. a
            # message too long to send as one SGPG envelope) so it can
            # be edited and resent instead of retyped from scratch.
            self._set_status(f"send failed: {exc}")
            return
        finally:
            zero(plaintext)
        composer.text = ""
        # Append directly instead of calling _render_contact(): we
        # already have the plaintext we just sent, so there's nothing
        # left to decrypt. A full re-render would re-decrypt every
        # message in the window (extra smartcard round trips for
        # messages already on screen) and, since that path suspends the
        # terminal for gpg-agent's pinentry, would visibly flash the
        # whole TUI closed and reopened on every single send.
        conversation = self.query_one("#conversation", ConversationView)
        conversation.add_bubble(who="You", text=text, mine=True, badge="🔐")


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
