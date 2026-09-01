from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator

import pytest

from sgpg.signal.client import SignalClient
from sgpg.signal.messages import parse_contact, parse_receive_notification
from sgpg.signal.rpc import JSONRPCClient, Notification, RPCConnectionError, RPCError


class LoopbackServer:
    """A tiny line-delimited JSON-RPC peer for exercising JSONRPCClient.

    Runs over a real localhost TCP socket rather than a hand-rolled fake
    stream pair, so JSONRPCClient is tested against genuine asyncio
    StreamReader/StreamWriter behavior.
    """

    def __init__(self) -> None:
        self.received: list[dict[str, object]] = []
        self.port: int = 0
        self._server: asyncio.AbstractServer | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._connected = asyncio.Event()

    async def start(self) -> int:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]  # type: ignore[index]
        return self.port

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._writer = writer
        self._connected.set()
        while True:
            line = await reader.readline()
            if not line:
                return
            self.received.append(json.loads(line))

    async def wait_connected(self) -> None:
        await self._connected.wait()

    async def send(self, message: dict[str, object]) -> None:
        await self.wait_connected()
        assert self._writer is not None
        self._writer.write((json.dumps(message) + "\n").encode("utf-8"))
        await self._writer.drain()

    async def close(self) -> None:
        if self._writer is not None:
            self._writer.close()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()


@pytest.fixture
async def server() -> AsyncIterator[LoopbackServer]:
    srv = LoopbackServer()
    await srv.start()
    yield srv
    await srv.close()


@pytest.fixture
async def client(server: LoopbackServer) -> AsyncIterator[JSONRPCClient]:
    reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
    rpc = JSONRPCClient(reader, writer)
    rpc.start()
    yield rpc
    await rpc.close()


@pytest.mark.asyncio
async def test_call_matches_response_by_id(server: LoopbackServer, client: JSONRPCClient) -> None:
    call_task = asyncio.ensure_future(client.call("send", {"recipient": ["+1555"]}))
    await server.wait_connected()
    for _ in range(50):
        if server.received:
            break
        await asyncio.sleep(0.01)
    request = server.received[0]
    assert request["method"] == "send"

    await server.send({"jsonrpc": "2.0", "id": request["id"], "result": {"timestamp": 123}})
    result = await asyncio.wait_for(call_task, timeout=5)
    assert result == {"timestamp": 123}


@pytest.mark.asyncio
async def test_call_raises_rpc_error_on_error_response(
    server: LoopbackServer, client: JSONRPCClient
) -> None:
    call_task = asyncio.ensure_future(client.call("bogus"))
    await server.wait_connected()
    for _ in range(50):
        if server.received:
            break
        await asyncio.sleep(0.01)
    request_id = server.received[0]["id"]

    await server.send(
        {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": "no such method"}}
    )
    with pytest.raises(RPCError):
        await asyncio.wait_for(call_task, timeout=5)


@pytest.mark.asyncio
async def test_unsolicited_message_dispatches_to_notification_handler(
    server: LoopbackServer, client: JSONRPCClient
) -> None:
    received: list[Notification] = []
    client.set_notification_handler(received.append)

    await server.send({"jsonrpc": "2.0", "method": "receive", "params": {"envelope": {}}})
    for _ in range(50):
        if received:
            break
        await asyncio.sleep(0.01)

    assert len(received) == 1
    assert received[0].method == "receive"


@pytest.mark.asyncio
async def test_pending_calls_fail_when_connection_closes(
    server: LoopbackServer, client: JSONRPCClient
) -> None:
    call_task = asyncio.ensure_future(client.call("send"))
    await server.wait_connected()
    await server.close()
    with pytest.raises(RPCConnectionError):
        await asyncio.wait_for(call_task, timeout=5)


class TestParseReceiveNotification:
    def test_ordinary_data_message(self) -> None:
        msg = parse_receive_notification(
            {
                "envelope": {
                    "sourceUuid": "uuid-1",
                    "sourceNumber": "+15551234567",
                    "dataMessage": {"message": "SGPG/1\n...", "timestamp": 42},
                },
                "account": "+15550000000",
            }
        )
        assert msg is not None
        assert msg.body == "SGPG/1\n..."
        assert msg.timestamp == 42
        assert msg.source_uuid == "uuid-1"
        assert not msg.is_sync_sent

    def test_sync_sent_message_marks_direction(self) -> None:
        msg = parse_receive_notification(
            {
                "envelope": {
                    "syncMessage": {
                        "sentMessage": {
                            "destinationNumber": "+15559999999",
                            "message": "hello from another device",
                            "timestamp": 99,
                        }
                    }
                }
            }
        )
        assert msg is not None
        assert msg.is_sync_sent
        assert msg.destination_number == "+15559999999"

    @pytest.mark.parametrize(
        "params",
        [
            None,
            {},
            {"envelope": {}},
            {"envelope": {"typingMessage": {"action": "STARTED"}}},
            {"envelope": {"receiptMessage": {"when": 1}}},
        ],
    )
    def test_non_message_notifications_return_none(self, params: object) -> None:
        assert parse_receive_notification(params) is None


class TestParseContact:
    def test_prefers_name_field(self) -> None:
        contact = parse_contact({"number": "+15551234567", "uuid": "u-1", "name": "Alice"})
        assert contact.name == "Alice"
        assert contact.number == "+15551234567"
        assert contact.uuid == "u-1"

    def test_falls_back_to_profile_name(self) -> None:
        contact = parse_contact({"number": "+1555", "profileName": "Alice P"})
        assert contact.name == "Alice P"

    def test_falls_back_to_given_and_family_name(self) -> None:
        contact = parse_contact({"givenName": "Alice", "familyName": "Example"})
        assert contact.name == "Alice Example"

    def test_no_name_available_is_none(self) -> None:
        contact = parse_contact({"number": "+1555"})
        assert contact.name is None


@pytest.mark.asyncio
async def test_list_contacts_sends_name_filter_and_parses_results(
    server: LoopbackServer, client: JSONRPCClient
) -> None:
    signal_client = SignalClient(client)
    call_task = asyncio.ensure_future(signal_client.list_contacts(name="Alice"))
    await server.wait_connected()
    for _ in range(50):
        if server.received:
            break
        await asyncio.sleep(0.01)
    request = server.received[0]
    assert request["method"] == "listContacts"
    assert request["params"] == {"name": "Alice"}

    await server.send(
        {
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": [{"number": "+15551234567", "uuid": "u-1", "name": "Alice"}],
        }
    )
    contacts = await asyncio.wait_for(call_task, timeout=5)
    assert len(contacts) == 1
    assert contacts[0].name == "Alice"
    assert contacts[0].number == "+15551234567"
