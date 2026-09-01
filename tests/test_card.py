from __future__ import annotations

import asyncio

import pytest

from sgpg.crypto import card

CARD_STATUS_OUTPUT = b"""\
AID:D276000124010304000600112233440000000000:
openpgp-card:
version:3.4:
vendor:Yubico:
serial:00061122:
name:::
lang::
sex:u:
url:
login:
forcepin:1:::
keyattr:1:1:2048:
keyattr:2:1:2048:
keyattr:3:1:2048:
maxpinlen:127:127:127:
pinretry:3:0:3:
sigcount:12:
cafpr:::
fpr:1111111111111111111111111111111111111111:2222222222222222222222222222222222222222:0000000000000000000000000000000000000000:
fprtime:1690000000:1690000000:0:
"""


class _FakeProcess:
    def __init__(self, stdout: bytes, returncode: int = 0) -> None:
        self._stdout = stdout
        self.returncode = returncode

    async def communicate(self) -> tuple[bytes, bytes]:
        return self._stdout, b""


@pytest.mark.asyncio
async def test_card_status_parses_fingerprints_and_zero_slots_as_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_exec(*_args: object, **_kwargs: object) -> _FakeProcess:
        return _FakeProcess(CARD_STATUS_OUTPUT)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    status = await card.card_status()
    assert status.present
    assert status.serial == "00061122"
    assert status.signing_fingerprint == "1" * 40
    assert status.encryption_fingerprint == "2" * 40
    assert status.authentication_fingerprint is None  # all-zero slot means "not set"
    assert status.fingerprints() == {"1" * 40, "2" * 40}


@pytest.mark.asyncio
async def test_card_status_is_absent_when_gpg_reports_no_card(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_exec(*_args: object, **_kwargs: object) -> _FakeProcess:
        return _FakeProcess(b"", returncode=2)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    status = await card.card_status()
    assert not status.present
    assert status.fingerprints() == frozenset()


def test_find_gpg_connect_agent_binary_raises_when_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(card.shutil, "which", lambda _name: None)
    with pytest.raises(card.GPGConnectAgentNotFoundError):
        card.find_gpg_connect_agent_binary()


@pytest.mark.asyncio
async def test_relearn_card_raises_on_agent_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(card.shutil, "which", lambda _name: "/usr/bin/gpg-connect-agent")

    async def fake_exec(*_args: object, **_kwargs: object) -> _FakeProcess:
        return _FakeProcess(b"ERR 67108924 No such device\n", returncode=1)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    with pytest.raises(card.CardRelearnError):
        await card.relearn_card()
