"""OpenPGP smartcard (e.g. YubiKey) status and relearn helpers.

Card fingerprints obtained here are used only to *describe* what a
decryption used (e.g. "Decrypted using YubiKey") -- never as a trust
decision. Trust always flows through the normal GnuPG keyring.
"""

from __future__ import annotations

import asyncio
import re
import shutil
from dataclasses import dataclass

_ALL_ZERO = re.compile(r"^0*$")

# The "fpr" record in `gpg --card-status --with-colons` output has three
# fingerprint columns: signature, encryption, authentication.
_CARD_FPR_FIELD_COUNT = 4


class GPGConnectAgentNotFoundError(Exception):
    """No ``gpg-connect-agent`` binary was found on PATH."""


class CardRelearnError(Exception):
    """The SCD LEARN sequence failed."""


@dataclass(frozen=True, slots=True)
class CardStatus:
    present: bool
    serial: str | None
    signing_fingerprint: str | None
    encryption_fingerprint: str | None
    authentication_fingerprint: str | None

    def fingerprints(self) -> frozenset[str]:
        return frozenset(
            fpr
            for fpr in (
                self.signing_fingerprint,
                self.encryption_fingerprint,
                self.authentication_fingerprint,
            )
            if fpr
        )


def _clean_fingerprint(value: str) -> str | None:
    value = value.strip()
    if not value or _ALL_ZERO.match(value):
        return None
    return value.upper()


async def card_status(gpg_binary: str = "gpg") -> CardStatus:
    """Query the currently inserted OpenPGP card, if any."""
    proc = await asyncio.create_subprocess_exec(
        gpg_binary,
        "--card-status",
        "--with-colons",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout_data, _stderr_data = await proc.communicate()
    if proc.returncode != 0:
        return CardStatus(
            present=False,
            serial=None,
            signing_fingerprint=None,
            encryption_fingerprint=None,
            authentication_fingerprint=None,
        )

    serial: str | None = None
    sig_fpr = enc_fpr = auth_fpr = None
    for line in stdout_data.decode("utf-8", errors="replace").splitlines():
        fields = line.split(":")
        if fields[0] == "serial" and len(fields) > 1:
            serial = fields[1] or None
        elif fields[0] == "fpr" and len(fields) >= _CARD_FPR_FIELD_COUNT:
            sig_fpr = _clean_fingerprint(fields[1])
            enc_fpr = _clean_fingerprint(fields[2])
            auth_fpr = _clean_fingerprint(fields[3])

    return CardStatus(
        present=serial is not None,
        serial=serial,
        signing_fingerprint=sig_fpr,
        encryption_fingerprint=enc_fpr,
        authentication_fingerprint=auth_fpr,
    )


def find_gpg_connect_agent_binary() -> str:
    path = shutil.which("gpg-connect-agent")
    if not path:
        raise GPGConnectAgentNotFoundError("gpg-connect-agent not found on PATH")
    return path


async def relearn_card() -> str:
    """Re-run GnuPG's card relearn sequence (``SCD SERIALNO`` / ``SCD LEARN --force``).

    Useful after swapping to a backup YubiKey holding cloned subkeys, so
    gpg-agent updates its idea of which card is present without the user
    needing to remember the raw ``gpg-connect-agent`` invocation.
    """
    binary = find_gpg_connect_agent_binary()
    proc = await asyncio.create_subprocess_exec(
        binary,
        "SCD SERIALNO",
        "SCD LEARN --force",
        "/bye",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout_data, stderr_data = await proc.communicate()
    output = stdout_data.decode("utf-8", errors="replace")
    if proc.returncode != 0 or "ERR" in output:
        raise CardRelearnError(output or stderr_data.decode("utf-8", errors="replace"))
    return output
