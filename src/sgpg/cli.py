"""The headless CLI layer.

Every important operation is available as a plain command so the TUI
can stay a presentation layer over these same tested primitives. No
command ever accepts message plaintext as an argument or option --
see ``_read_plaintext_from_stdin`` -- and no command ever writes
plaintext to a temp file.
"""

from __future__ import annotations

import asyncio
import sys
from collections.abc import AsyncIterator, Coroutine
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, TypeVar

import typer
from rich.console import Console
from rich.table import Table

from sgpg import paths
from sgpg.app import SgpgApp
from sgpg.contacts.resolver import ContactResolver, UnresolvedContactError, UnusableKeyError
from sgpg.contacts.store import ContactStore, ContactStoreError, DuplicateContactError
from sgpg.crypto import card as card_module
from sgpg.crypto.gpg import GPG, GPGEncryptionError, GPGNotFoundError, normalize_fingerprint, zero
from sgpg.history import MetadataStore
from sgpg.security import core_dumps_disabled, debug_logging_disabled, harden_process
from sgpg.signal.client import (
    DaemonStartTimeoutError,
    SignalCliNotFoundError,
    connect,
    daemon_session,
    find_signal_cli_binary,
    signal_cli_version,
)
from sgpg.signal.messages import SignalContact

T = TypeVar("T")

console = Console()
err_console = Console(stderr=True)

app = typer.Typer(
    pretty_exceptions_show_locals=False,  # a traceback must never render plaintext
    no_args_is_help=False,
    add_completion=False,
)
contact_app = typer.Typer(help="Manage the Signal <-> GPG contact mapping.")
key_app = typer.Typer(help="Inspect/import GPG keys.")
card_app = typer.Typer(help="OpenPGP smartcard (YubiKey) helpers.")
identity_app = typer.Typer(help="Your own GPG identity (used for encrypt-to-self).")
app.add_typer(contact_app, name="contact")
app.add_typer(key_app, name="key")
app.add_typer(card_app, name="card")
app.add_typer(identity_app, name="identity")


@dataclass(slots=True)
class GlobalOptions:
    gnupghome: str | None
    contacts_path: Path
    history_path: Path
    socket_path: Path
    account: str | None
    auto_daemon: bool


def _run(coro: Coroutine[object, object, T]) -> T:
    return asyncio.run(coro)


def _opts(ctx: typer.Context) -> GlobalOptions:
    return ctx.obj  # type: ignore[no-any-return]


def _read_plaintext_from_stdin() -> bytearray:
    """Read message plaintext from stdin -- never from argv, never a temp file.

    If stdin is a TTY, prompts for multi-line input terminated by EOF
    (Ctrl-D). If stdin is piped/redirected, reads it whole.
    """
    if sys.stdin.isatty():
        err_console.print("[dim]Write your message. Press Ctrl-D on a new line to send.[/dim]")
    data = sys.stdin.buffer.read()
    return bytearray(data)


@asynccontextmanager
async def _daemon_scope(opts: GlobalOptions) -> AsyncIterator[None]:
    """Spawn signal-cli's daemon for the duration of this block if it isn't
    already running, and stop it again on the way out -- but only if we're
    the one who started it (a daemon we didn't start might be serving
    something else, so we always leave that alone).
    """
    if not opts.auto_daemon:
        yield
        return
    try:
        async with daemon_session(opts.socket_path, account=opts.account) as spawned:
            if spawned:
                console.print("[green]✓[/green] started signal-cli daemon")
            yield
    except SignalCliNotFoundError:
        yield  # surfaced by the normal "signal-cli not found" paths elsewhere
    except DaemonStartTimeoutError as exc:
        err_console.print(f"[yellow]![/yellow] {exc}")
        yield


@asynccontextmanager
async def _open_app(opts: GlobalOptions) -> AsyncIterator[SgpgApp]:
    gpg = GPG(gnupghome=opts.gnupghome)
    contacts = ContactStore(opts.contacts_path)
    history = MetadataStore(opts.history_path)
    try:
        try:
            async with (
                _daemon_scope(opts),
                connect(opts.socket_path, account=opts.account) as signal,
            ):
                yield SgpgApp(gpg=gpg, contacts=contacts, signal=signal, history=history)
        except OSError as exc:
            err_console.print(
                f"[red]✗[/red] can't reach the Signal daemon at {opts.socket_path}: {exc}\n"
                f"  Start it with: signal-cli -a <number> daemon --socket {opts.socket_path}"
            )
            raise typer.Exit(code=1) from None
    finally:
        contacts.save()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    gnupghome: Annotated[
        str | None, typer.Option(help="Override GNUPGHOME (defaults to gpg's own default).")
    ] = None,
    contacts_path: Annotated[
        Path | None, typer.Option(help="Path to the contacts TOML file.")
    ] = None,
    history_path: Annotated[
        Path | None, typer.Option(help="Path to the local metadata/ciphertext SQLite database.")
    ] = None,
    socket_path: Annotated[
        Path | None, typer.Option(help="Path to signal-cli's JSON-RPC daemon socket.")
    ] = None,
    account: Annotated[
        str | None,
        typer.Option(
            help="Signal account (phone number) to use, if ambiguous. "
            "Defaults to the one set via 'sgpg identity set-account'."
        ),
    ] = None,
    auto_daemon: Annotated[
        bool,
        typer.Option(
            "--auto-daemon/--no-auto-daemon",
            help="Auto-start signal-cli's daemon if it isn't already running.",
        ),
    ] = True,
) -> None:
    harden_process()
    resolved_contacts_path = contacts_path or paths.contacts_path()
    resolved_history_path = history_path or paths.metadata_db_path()
    resolved_socket_path = socket_path or paths.signal_socket_path()
    resolved_account = account or ContactStore(resolved_contacts_path).identity_account()
    ctx.obj = GlobalOptions(
        gnupghome=gnupghome,
        contacts_path=resolved_contacts_path,
        history_path=resolved_history_path,
        socket_path=resolved_socket_path,
        account=resolved_account,
        auto_daemon=auto_daemon,
    )
    if ctx.invoked_subcommand is None:
        from sgpg.tui.app import run_tui  # noqa: PLC0415 - keep textual off the fast CLI path

        run_tui(
            gnupghome=gnupghome,
            contacts_path=resolved_contacts_path,
            history_path=resolved_history_path,
            socket_path=resolved_socket_path,
            account=resolved_account,
            auto_daemon=auto_daemon,
        )


@app.command()
def chat(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Contact to open the chat UI on.")],
) -> None:
    """Open the Textual chat UI directly on one contact."""
    opts = _opts(ctx)
    from sgpg.tui.app import run_tui  # noqa: PLC0415 - keep textual off the fast CLI path

    run_tui(
        gnupghome=opts.gnupghome,
        contacts_path=opts.contacts_path,
        history_path=opts.history_path,
        socket_path=opts.socket_path,
        account=opts.account,
        auto_daemon=opts.auto_daemon,
        initial_contact=name,
    )


@app.command()
def send(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Contact to send to.")],
    sign: Annotated[bool, typer.Option("--sign", help="Also sign the message.")] = False,
) -> None:
    """Encrypt a message (from stdin) to NAME and send it over Signal."""
    opts = _opts(ctx)
    plaintext = _read_plaintext_from_stdin()

    async def _do() -> None:
        async with _open_app(opts) as sgpg_app:
            try:
                receipt = await sgpg_app.send(name, plaintext, sign=sign)
            except (UnresolvedContactError, UnusableKeyError) as exc:
                err_console.print(f"[red]✗[/red] {exc}")
                raise typer.Exit(code=1) from None
            except GPGEncryptionError as exc:
                err_console.print(f"[red]✗ encryption failed:[/red] {exc}")
                raise typer.Exit(code=1) from None
            console.print(
                f"[green]✓[/green] sent to {receipt.contact_name}"
                + (" (signed)" if receipt.signed else "")
            )

    try:
        _run(_do())
    finally:
        zero(plaintext)


@app.command()
def read(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Contact whose conversation to read.")],
    n: Annotated[int, typer.Option("-n", help="Number of recent messages to decrypt.")] = 20,
) -> None:
    """Decrypt and print the last N messages with NAME. Plaintext is never persisted."""
    opts = _opts(ctx)

    async def _do() -> None:
        gpg = GPG(gnupghome=opts.gnupghome)
        contacts = ContactStore(opts.contacts_path)
        history = MetadataStore(opts.history_path)
        # Reading already-received history never needs a live Signal connection.
        sgpg_app = SgpgApp(gpg=gpg, contacts=contacts, history=history)
        rendered = await sgpg_app.read(name, limit=n)
        try:
            for msg in rendered:
                who = "you" if msg.direction == "outgoing" else name
                if msg.decrypted is not None:
                    text = msg.decrypted.plaintext.decode("utf-8", errors="replace")
                    console.print(f"[bold]{who}[/bold] ({msg.signal_timestamp}): {text}")
                else:
                    console.print(
                        f"[dim]{who} ({msg.signal_timestamp}): "
                        f"<{msg.error or 'undecryptable'}>[/dim]"
                    )
        finally:
            for msg in rendered:
                if msg.decrypted is not None:
                    msg.decrypted.wipe()

    _run(_do())


@app.command()
def inbox(ctx: typer.Context) -> None:
    """List contacts with recent activity, most recent first."""
    opts = _opts(ctx)
    history = MetadataStore(opts.history_path)
    table = Table(title="Inbox")
    table.add_column("Contact")
    table.add_column("Last seen (ms epoch)")
    for name, ts in history.inbox():
        table.add_row(name, str(ts))
    console.print(table)


async def _doctor_check_binaries(opts: GlobalOptions) -> GPG | None:
    try:
        gpg = GPG(gnupghome=opts.gnupghome)
        console.print(f"[green]✓[/green] gpg found: {await gpg.version()}")
    except GPGNotFoundError as exc:
        console.print(f"[red]✗[/red] gpg not found: {exc}")
        return None

    try:
        find_signal_cli_binary()
        console.print(f"[green]✓[/green] signal-cli found: {await signal_cli_version()}")
        console.print(
            "  [dim]Signal changes its server-side protocol over time and doesn't "
            "officially support third-party clients -- if sending/receiving suddenly "
            "stops working, update signal-cli before looking anywhere else.[/dim]"
        )
    except SignalCliNotFoundError:
        console.print("[red]✗[/red] signal-cli not found on PATH")

    if opts.socket_path.exists():
        try:
            async with connect(opts.socket_path, account=opts.account):
                console.print("[green]✓[/green] Signal daemon reachable")
        except OSError:
            console.print("[red]✗[/red] Signal daemon socket present but not reachable")
    else:
        console.print(
            "[yellow]![/yellow] no Signal daemon running right now -- expected unless "
            "you're mid-session; sgpg starts one on demand for send/chat/etc. "
            f"(socket: {opts.socket_path})"
        )
    return gpg


async def _doctor_check_identity(gpg: GPG | None, contacts: ContactStore) -> None:
    console.print("\n[bold]Identity:[/bold]")
    fpr = contacts.identity_fingerprint()
    if fpr and gpg is not None and await gpg.fingerprint_info(fpr) is not None:
        console.print(f"[green]✓[/green] {fpr}")
    elif fpr:
        console.print(f"[red]✗[/red] {fpr} (not found in keyring)")
    else:
        console.print("[red]✗[/red] no identity configured. Run: sgpg identity set <fingerprint>")

    account = contacts.identity_account()
    if account:
        console.print(f"[green]✓[/green] Signal account: {account}")
    else:
        console.print(
            "[yellow]![/yellow] no Signal account configured. "
            "Run: sgpg identity set-account <phone_number>"
        )


async def _doctor_check_card(gpg: GPG | None) -> None:
    console.print("\n[bold]YubiKey:[/bold]")
    status = await card_module.card_status(gpg.binary_path if gpg else "gpg")
    if not status.present:
        console.print("[yellow]![/yellow] no OpenPGP card detected")
        return
    console.print(f"[green]✓[/green] OpenPGP card detected (serial {status.serial})")
    sign_mark = "[green]✓[/green]" if status.signing_fingerprint else "[yellow]![/yellow]"
    enc_mark = "[green]✓[/green]" if status.encryption_fingerprint else "[yellow]![/yellow]"
    console.print(f"{sign_mark} signing subkey available")
    console.print(f"{enc_mark} encryption subkey available")


async def _doctor_check_contacts(gpg: GPG | None, contacts: ContactStore) -> None:
    console.print("\n[bold]Contacts:[/bold]")
    all_contacts = contacts.list_contacts()
    console.print(f"[green]✓[/green] {len(all_contacts)} contacts")
    if gpg is None:
        return
    expired = 0
    for c in all_contacts:
        if not c.gpg_fingerprint:
            continue
        key = await gpg.fingerprint_info(c.gpg_fingerprint)
        if key is not None and (key.expired or key.revoked):
            expired += 1
    if expired:
        console.print(f"[yellow]![/yellow] {expired} contact(s) have expired/revoked keys")


def _doctor_check_hardening() -> None:
    console.print("\n[bold]Plaintext persistence:[/bold]")
    debug_mark = "[green]✓[/green]" if debug_logging_disabled() else "[red]✗[/red]"
    core_mark = "[green]✓[/green]" if core_dumps_disabled() else "[red]✗[/red]"
    console.print(f"{debug_mark} debug logging disabled")
    console.print(f"{core_mark} core dumps disabled")


@app.command()
def doctor(ctx: typer.Context) -> None:
    """Report whether sgpg's security configuration is actually working."""
    opts = _opts(ctx)

    async def _do() -> None:
        gpg = await _doctor_check_binaries(opts)
        contacts = ContactStore(opts.contacts_path)
        await _doctor_check_identity(gpg, contacts)
        await _doctor_check_card(gpg)
        await _doctor_check_contacts(gpg, contacts)
        _doctor_check_hardening()

    _run(_do())


# -- contact subcommands -----------------------------------------------------


@contact_app.command("list")
def contact_list(ctx: typer.Context) -> None:
    opts = _opts(ctx)
    contacts = ContactStore(opts.contacts_path)
    table = Table()
    table.add_column("Name")
    table.add_column("Signal")
    table.add_column("GPG fingerprint")
    for c in contacts.list_contacts():
        table.add_row(c.name, c.signal_uuid or c.signal_number or "-", c.gpg_fingerprint or "-")
    console.print(table)


async def _resolve_signal_identity(
    opts: GlobalOptions, *, name: str, signal_uuid: str | None, signal_number: str | None
) -> tuple[str | None, str | None]:
    """Find a contact's Signal UUID/number: from flags, from a live Signal
    contact search, or (if the daemon is unreachable/no match) by prompting.
    """
    if signal_uuid or signal_number:
        return signal_uuid, signal_number

    candidates: list[SignalContact] = []
    try:
        async with (
            _daemon_scope(opts),
            connect(opts.socket_path, account=opts.account) as signal,
        ):
            candidates = await signal.list_contacts(name=name)
    except OSError:
        err_console.print("[yellow]![/yellow] can't reach the Signal daemon to look up contacts.")

    if not candidates:
        number = typer.prompt("Signal phone number (or leave blank for UUID)", default="")
        uuid_ = typer.prompt("Signal UUID") if not number else None
        return uuid_, (number or None)

    console.print(f'\nSignal contacts matching "{name}":\n')
    for i, c in enumerate(candidates, start=1):
        console.print(f"{i}. {c.name or '(no name)'}  {c.number or c.uuid or '?'}")
    choice = typer.prompt("Select contact", type=int)
    if not (1 <= choice <= len(candidates)):
        err_console.print("[red]✗[/red] invalid selection")
        raise typer.Exit(code=1)
    selected = candidates[choice - 1]
    return selected.uuid, selected.number


@contact_app.command("add")
def contact_add(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Local nickname for this contact.")],
    signal_uuid: Annotated[
        str | None, typer.Option(help="Contact's Signal UUID (skips the Signal lookup).")
    ] = None,
    signal_number: Annotated[
        str | None, typer.Option(help="Contact's Signal phone number (skips the Signal lookup).")
    ] = None,
    query: Annotated[
        str | None, typer.Option(help="GPG keyring search query (default: NAME).")
    ] = None,
) -> None:
    """Add a contact: find them in Signal, then associate a local GPG key.

    Never trusts a key just because it arrived over Signal: the key
    must already be in your keyring, and you must confirm its
    fingerprint out-of-band.
    """
    opts = _opts(ctx)

    async def _do() -> None:
        resolved_uuid, resolved_number = await _resolve_signal_identity(
            opts, name=name, signal_uuid=signal_uuid, signal_number=signal_number
        )

        gpg = GPG(gnupghome=opts.gnupghome)
        contacts = ContactStore(opts.contacts_path)
        candidates = await gpg.search_keys(query or name)
        if not candidates:
            err_console.print(
                f"[red]✗[/red] no GPG keys match {query or name!r}. "
                "Import one first with 'sgpg key import'."
            )
            raise typer.Exit(code=1)

        console.print(f'\nGPG keys matching "{query or name}":\n')
        for i, key in enumerate(candidates, start=1):
            uid = key.uids[0] if key.uids else "(no user id)"
            spaced = " ".join(key.fingerprint[j : j + 4] for j in range(0, len(key.fingerprint), 4))
            usable = key.can_encrypt and not key.expired and not key.revoked
            enc = "valid" if usable else "unusable"
            expiry = key.expiry.date().isoformat() if key.expiry else "never"
            console.print(f"{i}. {uid}\n   {spaced}\n   Encryption: {enc}\n   Expires: {expiry}\n")

        choice = typer.prompt("Select key", type=int)
        if not (1 <= choice <= len(candidates)):
            err_console.print("[red]✗[/red] invalid selection")
            raise typer.Exit(code=1)
        selected = candidates[choice - 1]

        spaced = " ".join(
            selected.fingerprint[j : j + 4] for j in range(0, len(selected.fingerprint), 4)
        )
        console.print(f"\nVerify this fingerprint with {name} out-of-band:\n{spaced}\n")
        if not typer.confirm(f"Associate this key with {name}?", default=False):
            err_console.print("Aborted.")
            raise typer.Exit(code=1)

        contacts.add_contact(
            name,
            signal_uuid=resolved_uuid,
            signal_number=resolved_number,
            gpg_fingerprint=selected.fingerprint,
        )
        contacts.save()
        console.print(f"[green]✓[/green] added {name}")

    try:
        _run(_do())
    except DuplicateContactError as exc:
        err_console.print(f"[red]✗[/red] {exc}")
        raise typer.Exit(code=1) from None


@contact_app.command("show")
def contact_show(ctx: typer.Context, name: str) -> None:
    opts = _opts(ctx)

    async def _do() -> None:
        gpg = GPG(gnupghome=opts.gnupghome)
        contacts = ContactStore(opts.contacts_path)
        contact = contacts.get_contact(name)
        if contact is None:
            err_console.print(f"[red]✗[/red] no such contact: {name}")
            raise typer.Exit(code=1)
        console.print(contact)
        if contact.gpg_fingerprint:
            key = await gpg.fingerprint_info(contact.gpg_fingerprint)
            console.print(key)

    _run(_do())


@contact_app.command("set-key")
def contact_set_key(ctx: typer.Context, name: str, fingerprint: str) -> None:
    opts = _opts(ctx)
    contacts = ContactStore(opts.contacts_path)
    contacts.set_key(name, fingerprint)
    contacts.save()
    console.print(f"[green]✓[/green] {name} -> {fingerprint}")


@contact_app.command("verify")
def contact_verify(ctx: typer.Context, name: str) -> None:
    opts = _opts(ctx)

    async def _do() -> None:
        gpg = GPG(gnupghome=opts.gnupghome)
        contacts = ContactStore(opts.contacts_path)
        resolver = ContactResolver(contacts, gpg)
        try:
            resolved = await resolver.resolve(name)
        except (UnresolvedContactError, UnusableKeyError) as exc:
            err_console.print(f"[red]✗[/red] {exc}")
            raise typer.Exit(code=1) from None
        console.print(f"[green]✓[/green] {name}'s key is usable: {resolved.key.fingerprint}")

    _run(_do())


# -- identity subcommands ------------------------------------------------------


@identity_app.command("set")
def identity_set(ctx: typer.Context, fingerprint: str) -> None:
    """Set your own GPG fingerprint, used for encrypt-to-self and signing.

    Must be a key you hold the secret key for -- sgpg checks the local
    secret keyring, not just that the fingerprint is known.
    """
    opts = _opts(ctx)

    async def _do() -> None:
        gpg = GPG(gnupghome=opts.gnupghome)
        fpr = normalize_fingerprint(fingerprint)
        secret_fingerprints = await gpg.list_secret_key_fingerprints()
        if fpr not in secret_fingerprints:
            err_console.print(
                f"[red]✗[/red] no secret key for {fpr} in this keyring -- "
                "sgpg needs to decrypt/sign with your identity key, so it "
                "must be one you actually hold, not just a public key."
            )
            raise typer.Exit(code=1)

        contacts = ContactStore(opts.contacts_path)
        contacts.set_identity(fpr)
        contacts.save()
        console.print(f"[green]✓[/green] identity set to {fpr}")

    _run(_do())


@identity_app.command("set-account")
def identity_set_account(ctx: typer.Context, phone_number: str) -> None:
    """Set your Signal account (E.164 phone number, e.g. +15551234567).

    This becomes the default for --account, so you don't need to pass
    it on every command, and it's what a freshly auto-started daemon
    is pointed at.
    """
    opts = _opts(ctx)
    contacts = ContactStore(opts.contacts_path)
    try:
        contacts.set_identity_account(phone_number)
    except ContactStoreError as exc:
        err_console.print(f"[red]✗[/red] {exc}")
        raise typer.Exit(code=1) from None
    contacts.save()
    console.print(f"[green]✓[/green] Signal account set to {phone_number}")


@identity_app.command("show")
def identity_show(ctx: typer.Context) -> None:
    opts = _opts(ctx)
    contacts = ContactStore(opts.contacts_path)
    fpr = contacts.identity_fingerprint()
    account = contacts.identity_account()
    if fpr is None and account is None:
        err_console.print(
            "[red]✗[/red] no identity configured. Run: sgpg identity set <fingerprint>"
        )
        raise typer.Exit(code=1)
    console.print(f"GPG fingerprint: {fpr or '(not set)'}")
    console.print(f"Signal account:  {account or '(not set)'}")


# -- key subcommands ----------------------------------------------------------


@key_app.command("show")
def key_show(ctx: typer.Context, name: str) -> None:
    contact_show(ctx, name)


@key_app.command("import")
def key_import(ctx: typer.Context, key_file: Path) -> None:
    """Import a public key file (never a private key) via 'gpg --import'."""
    opts = _opts(ctx)
    data = key_file.read_bytes()

    async def _do() -> None:
        gpg = GPG(gnupghome=opts.gnupghome)
        result = await gpg.import_key(data)
        for fpr in result.fingerprints:
            console.print(f"[green]✓[/green] imported {fpr}")

    _run(_do())


# -- card subcommands -----------------------------------------------------------


@card_app.command("learn")
def card_learn(ctx: typer.Context) -> None:
    """Re-learn the currently inserted OpenPGP card (e.g. after a backup YubiKey swap)."""

    async def _do() -> None:
        output = await card_module.relearn_card()
        console.print(output or "[green]✓[/green] card relearned")

    _run(_do())
