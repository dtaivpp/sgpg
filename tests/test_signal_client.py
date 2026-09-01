"""Tests for the signal-cli daemon auto-start/auto-stop logic.

Everything here mocks the subprocess/socket layer -- these must never
spawn a real signal-cli process. A real one is slow-ish to start (JVM
boot, ~0.5s) and, if a test forgot to tear it down, would keep running
in the background pointed at a since-deleted tmp socket.
"""

from __future__ import annotations

import asyncio
import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from sgpg.signal import client


class _FakeProcess:
    """Stands in for asyncio.subprocess.Process well enough for daemon_session."""

    def __init__(self) -> None:
        self.returncode: int | None = None
        self.terminated = False
        self.killed = False

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = 0

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9

    async def wait(self) -> int:
        return self.returncode if self.returncode is not None else 0


@pytest.fixture
def short_tmp_dir() -> Iterator[Path]:
    """A short directory under /tmp, for tests that actually bind a real
    AF_UNIX socket -- sun_path has a ~104-108 byte limit, and pytest's own
    tmp_path is often too deeply nested to fit a socket file under it.
    """
    raw = tempfile.mkdtemp(prefix="sgpg-sock-", dir="/tmp")
    try:
        yield Path(raw)
    finally:
        shutil.rmtree(raw, ignore_errors=True)


@pytest.mark.asyncio
async def test_daemon_is_running_false_when_nothing_listens(tmp_path: Path) -> None:
    assert not await client.daemon_is_running(tmp_path / "no-such.sock")


@pytest.mark.asyncio
async def test_daemon_is_running_true_when_something_listens(short_tmp_dir: Path) -> None:
    socket_path = short_tmp_dir / "test.sock"
    server = await asyncio.start_unix_server(lambda _r, _w: None, path=str(socket_path))
    try:
        assert await client.daemon_is_running(socket_path)
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_daemon_session_leaves_an_already_running_daemon_alone(
    short_tmp_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """We only ever stop daemons we started ourselves."""
    socket_path = short_tmp_dir / "test.sock"
    server = await asyncio.start_unix_server(lambda _r, _w: None, path=str(socket_path))

    async def fail_if_spawned(*_a: object, **_k: object) -> _FakeProcess:
        raise AssertionError("should not spawn a daemon that's already running")

    monkeypatch.setattr(client, "spawn_daemon", fail_if_spawned)
    try:
        async with client.daemon_session(socket_path) as spawned:
            assert spawned is False
        # Still running after the block exits -- we didn't touch it.
        assert await client.daemon_is_running(socket_path)
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_daemon_session_spawns_waits_then_stops_it_on_exit(
    short_tmp_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A daemon we spawn is stopped again when the block exits -- its
    lifetime is scoped to ours, not left running in the background.
    """
    socket_path = short_tmp_dir / "test.sock"
    fake_proc = _FakeProcess()
    spawned_event = asyncio.Event()

    async def fake_spawn(*_a: object, **_k: object) -> _FakeProcess:
        spawned_event.set()
        return fake_proc

    async def bind_after_spawn() -> asyncio.AbstractServer:
        # Simulate the daemon taking a moment (JVM boot) to bind its socket.
        await spawned_event.wait()
        await asyncio.sleep(0.05)
        return await asyncio.start_unix_server(lambda _r, _w: None, path=str(socket_path))

    monkeypatch.setattr(client, "spawn_daemon", fake_spawn)
    bind_task = asyncio.ensure_future(bind_after_spawn())
    try:
        async with client.daemon_session(socket_path, timeout=5.0, poll_interval=0.02) as spawned:
            assert spawned is True
            assert not fake_proc.terminated
        assert fake_proc.terminated
    finally:
        server = await bind_task
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_daemon_session_raises_if_process_exits_immediately(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    socket_path = tmp_path / "test.sock"
    fake_proc = _FakeProcess()
    fake_proc.returncode = 1  # already exited by the time we check

    async def fake_spawn(*_a: object, **_k: object) -> _FakeProcess:
        return fake_proc

    monkeypatch.setattr(client, "spawn_daemon", fake_spawn)
    with pytest.raises(client.DaemonStartTimeoutError, match="exited immediately"):
        async with client.daemon_session(socket_path, timeout=1.0, poll_interval=0.02):
            pass


@pytest.mark.asyncio
async def test_daemon_session_stops_daemon_even_on_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A spawned-but-never-reachable daemon must still be cleaned up,
    not leaked as an orphan process."""
    socket_path = tmp_path / "never-appears.sock"
    fake_proc = _FakeProcess()

    async def fake_spawn(*_a: object, **_k: object) -> _FakeProcess:
        return fake_proc

    monkeypatch.setattr(client, "spawn_daemon", fake_spawn)
    with pytest.raises(client.DaemonStartTimeoutError, match="didn't become reachable"):
        async with client.daemon_session(socket_path, timeout=0.1, poll_interval=0.02):
            pass
    assert fake_proc.terminated


@pytest.mark.asyncio
async def test_signal_cli_version_reports_stdout(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeVersionProcess:
        async def communicate(self) -> tuple[bytes, bytes]:
            return b"signal-cli 0.14.7\n", b""

    async def fake_exec(*_args: object, **_kwargs: object) -> _FakeVersionProcess:
        return _FakeVersionProcess()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    version = await client.signal_cli_version(binary="signal-cli")
    assert version == "signal-cli 0.14.7"
