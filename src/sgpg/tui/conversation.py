"""Conversation view: renders decrypted message bubbles.

Plaintext lives in these widgets only for as long as a conversation is
open. Switching contacts or closing the app clears the mounted widgets
so nothing decrypted lingers on screen or in the widget tree.
"""

from __future__ import annotations

from textual.containers import VerticalScroll
from textual.widgets import Static


class ConversationView(VerticalScroll):
    def clear_conversation(self) -> None:
        self.remove_children()

    def add_bubble(self, *, who: str, text: str, mine: bool, badge: str = "") -> None:
        css_class = "bubble-mine" if mine else "bubble-theirs"
        header = f"[b]{who}[/b]" + (f"  {badge}" if badge else "")
        self.mount(Static(f"{header}\n{text}", classes=f"bubble {css_class}"))
        self.scroll_end(animate=False)

    def add_system(self, text: str) -> None:
        self.mount(Static(text, classes="bubble-system"))
        self.scroll_end(animate=False)
