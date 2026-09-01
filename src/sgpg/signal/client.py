"""High-level Signal client: talks to a running signal-cli JSON-RPC daemon.

We use the daemon's Unix-socket JSON-RPC interface rather than invoking
``signal-cli receive`` repeatedly and parsing human-readable output, so
incoming messages arrive as structured notifications instead of text we
would have to scrape.
"""

from __future__ import annotations

import asyncio
import contextlib
import shutil
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from sgpg.signal.messages import (
    IncomingMessage,
    SignalContact,
    parse_contact,
    parse_receive_notification,
)
from sgpg.signal.rpc import JSONRPCClient, Notification

__all__ = [
    "DaemonStartTimeoutError",
    "SignalCliNotFoundError",
    "SignalClient",
    "connect",
    "daemon_is_running",
    "daemon_session",
    "find_signal_cli_binary",
    "signal_cli_version",
    "spawn_daemon",
]


class SignalCliNotFoundError(Exception):
    pass


class DaemonStartTimeoutError(Exception):
    """The daemon was spawned but never became reachable in time.

    We deliberately don't capture the daemon's stdout/stderr for
    diagnosis here (see spawn_daemon's docstring) -- if this fires,
    the fix is to run `signal-cli daemon --socket ...` by hand once to
    see the real error (commonly: no account linked/registered yet).
    """


def find_signal_cli_binary() -> str:
    path = shutil.which("signal-cli")
    if not path:
        raise SignalCliNotFoundError("signal-cli not found on PATH")
    return path


async def signal_cli_version(binary: str | None = None) -> str:
    """Report the installed signal-cli version.

    Signal's own server-side protocol changes over time, and Signal Inc.
    doesn't officially support third-party clients -- an old signal-cli
    can start silently failing to send/receive with no local code change
    at all. Surfacing the version (see `sgpg doctor`) makes that
    diagnosable instead of mysterious.
    """
    proc = await asyncio.create_subprocess_exec(
        binary or find_signal_cli_binary(),
        "--version",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout_data, _ = await proc.communicate()
    return stdout_data.decode("utf-8", errors="replace").strip()


class SignalClient:
    """Wraps a JSONRPCClient with Signal-specific methods.

    Never encrypts or decrypts anything -- message bodies passed to
    send() and yielded from messages() are opaque strings as far as
    this class is concerned. Whether they're SGPG envelopes is decided
    by protocol/envelope.py, one layer up.
    """

    def __init__(self, rpc: JSONRPCClient, *, account: str | None = None) -> None:
        self._rpc = rpc
        self._account = account
        self._incoming: asyncio.Queue[IncomingMessage] = asyncio.Queue()
        rpc.set_notification_handler(self._handle_notification)

    def _handle_notification(self, notification: Notification) -> None:
        if notification.method != "receive":
            return
        message = parse_receive_notification(notification.params)
        if message is not None:
            self._incoming.put_nowait(message)

    def start(self) -> None:
        self._rpc.start()

    async def close(self) -> None:
        await self._rpc.close()

    async def send(self, recipient: str, message: str) -> None:
        params: dict[str, object] = {"recipient": [recipient], "message": message}
        if self._account:
            params["account"] = self._account
        await self._rpc.call("send", params)

    async def messages(self) -> AsyncIterator[IncomingMessage]:
        """Yield incoming messages (including sync-sent echoes of our own) forever."""
        while True:
            yield await self._incoming.get()

    async def list_identities(self) -> list[dict[str, object]]:
        params = {"account": self._account} if self._account else None
        result = await self._rpc.call("listIdentities", params)
        return list(result) if isinstance(result, list) else []

    async def list_contacts(self, *, name: str | None = None) -> list[SignalContact]:
        """Search your linked account's Signal contacts, optionally by name.

        Never trusts anything from this list as an encryption key --
        it's only used to find a contact's phone number/UUID for the
        Signal <-> GPG mapping. GPG keys are still resolved and verified
        separately, from the local keyring.
        """
        params: dict[str, object] = {}
        if self._account:
            params["account"] = self._account
        if name:
            params["name"] = name
        result = await self._rpc.call("listContacts", params or None)
        if not isinstance(result, list):
            return []
        return [parse_contact(item) for item in result if isinstance(item, dict)]


@asynccontextmanager
async def connect(socket_path: Path, *, account: str | None = None) -> AsyncIterator[SignalClient]:
    """Connect to an already-running ``signal-cli daemon --socket <path>``."""
    reader, writer = await asyncio.open_unix_connection(str(socket_path))
    rpc = JSONRPCClient(reader, writer)
    client = SignalClient(rpc, account=account)
    client.start()
    try:
        yield client
    finally:
        await client.close()


async def spawn_daemon(
    socket_path: Path, *, account: str | None = None, signal_cli_binary: str | None = None
) -> asyncio.subprocess.Process:
    """Launch ``signal-cli daemon --socket <path>`` as a subprocess.

    Runs in its own session (``start_new_session=True``) purely so a
    Ctrl-C / SIGINT sent to sgpg's process group doesn't also kill the
    daemon out from under us mid-shutdown -- we still explicitly stop
    it ourselves (see daemon_session) if we're the one who started it.

    The daemon's own stdout/stderr are redirected to DEVNULL: signal-cli
    logs could in principle echo message content back, and we make no
    promises about our own logs being safe for that, so we simply never
    capture the daemon's output. Use `signal-cli -v daemon ...` yourself,
    outside sgpg, if you need to debug the daemon directly.
    """
    binary = signal_cli_binary or find_signal_cli_binary()
    socket_path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    args = [binary]
    if account:
        args += ["-a", account]
    args += ["daemon", "--socket", str(socket_path)]
    return await asyncio.create_subprocess_exec(
        *args,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
        start_new_session=True,
    )


async def daemon_is_running(socket_path: Path) -> bool:
    """True if something is already listening on socket_path."""
    try:
        _reader, writer = await asyncio.open_unix_connection(str(socket_path))
    except OSError:
        return False
    writer.close()
    with contextlib.suppress(OSError):
        await writer.wait_closed()
    return True


async def _wait_until_reachable(
    proc: asyncio.subprocess.Process,
    socket_path: Path,
    *,
    timeout: float,
    poll_interval: float,
) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if proc.returncode is not None:
            raise DaemonStartTimeoutError(
                f"signal-cli daemon exited immediately (code {proc.returncode}) -- "
                "run 'signal-cli daemon --socket ...' by hand to see why "
                "(commonly: no account linked/registered yet)."
            )
        if await daemon_is_running(socket_path):
            return
        await asyncio.sleep(poll_interval)
    raise DaemonStartTimeoutError(
        f"signal-cli daemon didn't become reachable within {timeout:.0f}s"
    )


async def _stop_daemon(proc: asyncio.subprocess.Process) -> None:
    if proc.returncode is not None:
        return
    proc.terminate()
    try:
        await asyncio.wait_for(proc.wait(), timeout=5.0)
    except TimeoutError:
        proc.kill()
        await proc.wait()


@asynccontextmanager
async def daemon_session(
    socket_path: Path,
    *,
    account: str | None = None,
    signal_cli_binary: str | None = None,
    timeout: float = 20.0,
    poll_interval: float = 0.3,
) -> AsyncIterator[bool]:
    """Ensure a daemon is reachable for the duration of this block.

    If one is already running, this is a no-op -- it's left running
    when the block exits, since something else (you, another sgpg
    command) may depend on it and we only ever stop daemons we
    ourselves started. If we spawn a fresh one, we own it: it comes up
    for this block and is terminated again when the block exits,
    mirroring sgpg's own process lifetime rather than lingering in the
    background indefinitely.

    Yields True if we spawned (and own) the daemon, False if one was
    already running.
    """
    if await daemon_is_running(socket_path):
        yield False
        return

    proc = await spawn_daemon(socket_path, account=account, signal_cli_binary=signal_cli_binary)
    try:
        await _wait_until_reachable(proc, socket_path, timeout=timeout, poll_interval=poll_interval)
        yield True
    finally:
        await _stop_daemon(proc)
