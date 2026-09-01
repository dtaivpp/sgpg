"""Process-wide security hardening.

Applied once at startup (see ``__main__.py``). None of this substitutes
for the real invariants enforced elsewhere -- pipes-only GPG I/O, no
plaintext on disk, no plaintext in argv/env. It narrows the blast radius
of what's left: mainly, "don't let plaintext end up in a core dump or a
debug log."
"""

from __future__ import annotations

import logging
import sys

try:
    import resource
except ImportError:  # pragma: no cover - resource is POSIX-only
    resource = None  # type: ignore[assignment]


def disable_core_dumps() -> bool:
    """Best-effort: stop the OS from writing a core dump on crash.

    A core dump could contain decrypted plaintext still resident in
    memory. Returns True once core dumps are confirmed disabled.
    """
    if resource is None:
        return False
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ValueError, OSError):
        return False
    return core_dumps_disabled()


def core_dumps_disabled() -> bool:
    if resource is None:
        return False
    try:
        soft, _hard = resource.getrlimit(resource.RLIMIT_CORE)
    except (ValueError, OSError):
        return False
    return soft == 0


def debug_logging_disabled() -> bool:
    """True if the root logger is at WARNING or above.

    We never log message plaintext at any level, but keeping the default
    level conservative avoids a dependency accidentally logging request
    or response bodies at DEBUG.
    """
    return logging.getLogger().getEffectiveLevel() >= logging.WARNING


def harden_process() -> None:
    disable_core_dumps()
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
    logging.getLogger().setLevel(logging.WARNING)
