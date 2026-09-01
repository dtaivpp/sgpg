"""Sidebar contact list."""

from __future__ import annotations

from textual.widgets import Label, ListItem, ListView

from sgpg.contacts.store import Contact


class ContactListItem(ListItem):
    def __init__(self, name: str) -> None:
        self.contact_name = name
        super().__init__(Label(name))


def populate(list_view: ListView, contacts: list[Contact]) -> None:
    list_view.clear()
    for c in contacts:
        list_view.append(ContactListItem(c.name))
