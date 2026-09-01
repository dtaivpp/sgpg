"""Multi-line message composer.

Never writes to a temp file: message text lives only in this widget's
in-memory buffer until it is handed straight to gpg over stdin (see
SgpgApp.send), then the widget's own text is cleared.
"""

from __future__ import annotations

from typing import ClassVar

from textual.binding import BindingType
from textual.message import Message
from textual.widgets import TextArea


class Composer(TextArea):
    """A plain-text composer. Enter inserts a newline; Ctrl+J sends."""

    class SendRequested(Message):
        pass

    BINDINGS: ClassVar[list[BindingType]] = [("ctrl+j", "send", "Send message")]

    def action_send(self) -> None:
        self.post_message(self.SendRequested())

    def take_text(self) -> str:
        text = self.text
        self.text = ""
        return text
