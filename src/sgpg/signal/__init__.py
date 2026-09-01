"""Signal transport, via signal-cli's JSON-RPC daemon.

This package only moves bytes over Signal. It never touches
cryptography -- see crypto/gpg.py and protocol/envelope.py for that.
"""
