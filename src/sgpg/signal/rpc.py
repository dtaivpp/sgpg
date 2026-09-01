"""Minimal JSON-RPC 2.0 client over a newline-delimited stream.

Used to talk to ``signal-cli daemon --socket ...``. This module knows
nothing about Signal-specific methods or message shapes -- see
signal/client.py and signal/messages.py for that. Kept generic and
small deliberately: it is easy to unit test with an in-memory stream
pair instead of a real daemon.
"""

from __future__ import annotations

import asyncio
import contextlib
import itertools
import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


class RPCError(Exception):
    def __init__(self, code: int, message: str, data: Any = None) -> None:
        self.code = code
        self.data = data
        super().__init__(f"JSON-RPC error {code}: {message}")


class RPCConnectionError(Exception):
    """The underlying stream closed while a request was pending."""


@dataclass(frozen=True, slots=True)
class Notification:
    method: str
    params: Any


NotificationHandler = Callable[[Notification], None]


class JSONRPCClient:
    """A JSON-RPC 2.0 client speaking newline-delimited JSON over a stream.

    Requests we send are matched to their responses by id. Anything the
    peer sends without a matching pending request id -- i.e. a genuine
    server-initiated notification, like signal-cli's unsolicited
    "receive" -- is handed to the notification handler.
    """

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        on_notification: NotificationHandler | None = None,
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._on_notification = on_notification
        self._id_counter = itertools.count(1)
        self._pending: dict[int, asyncio.Future[Any]] = {}
        self._read_task: asyncio.Task[None] | None = None
        self._closed = False

    def set_notification_handler(self, handler: NotificationHandler | None) -> None:
        self._on_notification = handler

    def start(self) -> None:
        self._read_task = asyncio.ensure_future(self._read_loop())

    async def close(self) -> None:
        self._closed = True
        if self._read_task is not None:
            self._read_task.cancel()
        self._writer.close()
        with contextlib.suppress(OSError):
            await self._writer.wait_closed()

    async def call(self, method: str, params: dict[str, Any] | None = None) -> Any:
        request_id = next(self._id_counter)
        payload: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            payload["params"] = params

        future: asyncio.Future[Any] = asyncio.get_running_loop().create_future()
        self._pending[request_id] = future
        try:
            self._writer.write((json.dumps(payload) + "\n").encode("utf-8"))
            await self._writer.drain()
            return await future
        finally:
            self._pending.pop(request_id, None)

    async def _read_loop(self) -> None:
        try:
            while not self._closed:
                line = await self._reader.readline()
                if not line:
                    break
                self._handle_line(line)
        except asyncio.CancelledError:
            raise
        except (ConnectionResetError, OSError):
            pass
        finally:
            for future in self._pending.values():
                if not future.done():
                    future.set_exception(RPCConnectionError("connection closed"))

    def _handle_line(self, line: bytes) -> None:
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            return  # ignore malformed lines rather than crash the reader loop

        has_id = "id" in message and message["id"] is not None
        if has_id and ("result" in message or "error" in message):
            future = self._pending.get(message["id"])
            if future is None or future.done():
                return
            error = message.get("error")
            if error is not None:
                future.set_exception(
                    RPCError(error.get("code", 0), error.get("message", ""), error.get("data"))
                )
            else:
                future.set_result(message.get("result"))
            return

        method = message.get("method")
        if method and self._on_notification is not None:
            self._on_notification(Notification(method=method, params=message.get("params")))
