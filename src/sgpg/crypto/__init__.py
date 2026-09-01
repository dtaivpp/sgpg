"""GPG-backed cryptography adapter.

Nothing in this package implements cryptographic primitives. Every
function here is a disciplined subprocess wrapper around the system
``gpg`` binary and its machine-readable status protocol.
"""
