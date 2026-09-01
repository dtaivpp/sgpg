Yes. I’d build this as a small security-focused Python CLI/TUI where **GPG remains the source of truth for keys**, Signal is only transport, and the wrapper stores only metadata/mappings—not plaintext messages or duplicate public-key material.

## Getting started

This design is implemented. Requires `gpg` and `signal-cli` on `PATH`
(`brew install gnupg signal-cli` on macOS) and Python 3.11+.

```bash
uv sync --group dev        # install deps into .venv
uv run pytest               # 90+ tests, isolated test GnuPG keyring
uv run ruff check .         # lint (includes flake8-bandit security rules)
uv run mypy                 # strict type checking

uv run sgpg doctor           # check your real gpg/signal-cli setup
uv run sgpg contact add alice --signal-number +15551234567
uv run sgpg send alice       # reads plaintext from stdin, never argv
uv run sgpg read alice -n 20
uv run sgpg                  # bare invocation launches the Textual chat UI
```

Signal transport needs a running daemon first:

```bash
signal-cli -a +1YOURNUMBER daemon --socket ~/.local/share/sgpg/signal-cli.sock
```

Project layout matches the "Suggested project structure" below, plus a
few modules the build revealed were necessary: `paths.py` (XDG
locations), `security.py` (core-dump/log hardening), `history.py` (the
SQLite metadata + local ciphertext store -- signal-cli's JSON-RPC has
no history-replay method, so "decrypt the last N messages" requires
`sgpg` to keep its own copy of the SGPG ciphertext, per invariant #8),
and `app.py` (the composition root both the CLI and TUI are thin
layers over).

## Core design

The wrapper should never maintain its own cryptographic key store. Known people’s public keys live in your normal GnuPG keyring, and the app maps a Signal identity to a **full GPG fingerprint**.

That gives us:

```text
Signal user/UUID/number
        │
        ▼
local contact mapping
        │
        ▼
GPG fingerprint
        │
        ▼
normal GnuPG keyring
```

For encryption, use GPG by full fingerprint. GnuPG already supports recipient selection by fingerprint, and `--encrypt-to` is specifically intended for automatically encrypting a copy to yourself. ([GnuPG][1])

Conceptually:

```bash
gpg \
  --armor \
  --encrypt \
  --recipient RECIPIENT_FINGERPRINT \
  --encrypt-to YOUR_FINGERPRINT
```

That means every outgoing message has two recipients:

```text
recipient's encryption subkey
your encryption subkey
```

So both sides can decrypt the same ciphertext.

## Security invariants

These should be treated as requirements, not nice-to-haves:

1. **No plaintext message database.**
2. **No plaintext temporary files.**
3. **No message body in command-line arguments.**
4. **No private-key handling in Python.**
5. **No custom crypto.**
6. **All encryption/decryption goes through `gpg`.**
7. **All GPG input/output goes through pipes.**
8. **Ciphertext may be persisted; plaintext may not.**
9. **Contact mappings contain fingerprints only, never copied public keys.**
10. **Decrypted messages exist only in process/terminal memory for the duration of viewing.**

The Python process would do something equivalent to:

```text
Python plaintext bytes
      │ stdin
      ▼
     gpg
      │ stdout
      ▼
armored ciphertext
      │
      ▼
 signal-cli
```

Receiving reverses it:

```text
signal-cli
    │
    ▼
ciphertext
    │ stdin
    ▼
   gpg
    │ stdout
    ▼
Python UI
```

No `/tmp/message.txt`.

## Signal integration

I would use `signal-cli`'s **JSON-RPC daemon interface**, rather than invoking `signal-cli receive` repeatedly and parsing human-readable output.

Current `signal-cli` supports JSON-RPC over stdin/stdout as well as daemon modes over Unix sockets, TCP, and HTTP. Incoming messages arrive as structured `receive` notifications. ([GitHub][2])

I'd prefer:

```text
signal-cli daemon --socket
```

and have our application communicate over the Unix socket.

That gives us a clean boundary:

```text
┌───────────────────────────────┐
│ sgpg                          │
│                               │
│ TUI ── contacts ── GPG        │
│  │                    │       │
│  │                    └YubiKey│
│  │                            │
│  └──── Signal RPC client ─────┼──▶ signal-cli
└───────────────────────────────┘
```

## Contact model

Something very small, perhaps:

```toml
[identity]
gpg_fingerprint = "EBAAD74D6C1534378C0066089A1D947AAB60EEE7"

[contacts.alice]
signal_uuid = "..."
signal_number = "+15551234567"
gpg_fingerprint = "0123456789ABCDEF0123456789ABCDEF01234567"

[contacts.bob]
signal_uuid = "..."
gpg_fingerprint = "89ABCDEF..."
```

The **fingerprint is merely a pointer into GPG**.

We would validate it by asking GPG:

```bash
gpg --with-colons --fingerprint FINGERPRINT
```

and obtain encryption-capable subkey information from GPG rather than duplicating it into our config.

### Adding a contact

UX:

```text
$ sgpg contact add alice

Signal contact:
> Alice (+1•••)

GPG keys matching "Alice":

1. Alice Example <alice@example.com>
   0123 4567 89AB CDEF ...
   Encryption: valid
   Expires: 2029-04-18

Select key: 1

Verify this fingerprint with Alice out-of-band:
0123 4567 89AB CDEF ...

Associate this key with Alice? [y/N]
```

It should **not automatically trust a key because someone sent it over Signal**.

Key import could be supported:

```text
sgpg key import alice.asc
```

but internally that's simply:

```bash
gpg --import
```

Then the mapping points to its fingerprint.

## CLI layer

Even though the eventual interface will be a chat TUI, I’d keep every important operation available as a regular CLI command.

Something like:

```text
sgpg
sgpg chat alice
sgpg send alice
sgpg inbox
sgpg read alice
sgpg read alice -n 20

sgpg contact list
sgpg contact add alice
sgpg contact show alice
sgpg contact set-key alice <fingerprint>
sgpg contact verify alice

sgpg key show alice
sgpg doctor
```

This is valuable because the TUI becomes a presentation layer over tested primitives rather than containing all the business logic itself.

## Sending

`sgpg send alice` would:

```text
1. Resolve Alice → Signal identity
2. Resolve Alice → GPG fingerprint
3. Ask GPG whether the key is usable
4. Accept plaintext via stdin/editor UI
5. Pipe plaintext directly into GPG
6. Encrypt to:
      Alice
      yourself
7. Receive armored ciphertext from stdout
8. Pass ciphertext to signal-cli
9. Destroy Python plaintext references
```

The actual GPG shape would likely be:

```bash
gpg \
  --batch \
  --yes \
  --armor \
  --recipient ALICE_FINGERPRINT \
  --encrypt-to YOUR_FINGERPRINT \
  --encrypt
```

We should **not use `--trust-model always` globally**. GnuPG has its own trust machinery, including Web of Trust and TOFU models, and we should preserve that rather than silently bypassing it. ([GnuPG][3])

## Message envelope

I would wrap the armored payload with a tiny version marker:

```text
SGPG/1
-----BEGIN PGP MESSAGE-----

...
-----END PGP MESSAGE-----
```

That gives us future extensibility without inventing crypto.

For example someday:

```text
SGPG/2
Content-Type: text/plain
...
```

But **version 1 should contain almost nothing except the PGP message.**

## Receiving

Incoming Signal messages would be classified into:

```text
ordinary Signal message
SGPG encrypted message
unsupported SGPG version
malformed SGPG message
```

Normal Signal messages should never accidentally be fed through GPG.

For encrypted ones:

```text
Signal ciphertext
      ↓
parse envelope
      ↓
gpg --decrypt
      ↓
capture plaintext in memory
      ↓
render
      ↓
discard
```

And GPG's stderr/status channel should be parsed separately so the UI can display:

```text
✓ Decrypted using YubiKey
✓ Encrypted to your key
Unsigned message
```

or, later:

```text
✓ Valid signature
  Alice Example
  0123 4567 ...
```

## Chat UI

This is where I think the project becomes genuinely pleasant to use.

I'd use **Textual**. It's an actively maintained Python TUI framework supporting macOS/Linux/Windows and asynchronous interactive applications, which fits our Signal RPC/event-loop model well. ([GitHub][4])

Think Claude/modern chat UI:

```text
┌ sgpg ─ Alice ────────────────────────────────────────┐
│                                                     │
│  Alice                                  08:14       │
│  Did the deploy finish?                            │
│                                                     │
│                              You        08:16       │
│                     Yep, everything looks good.    │
│                                                     │
│  Alice                                  08:18       │
│  Great. Let's ship it.                             │
│                                                     │
│                                                     │
├─────────────────────────────────────────────────────┤
│ Write a message…                                   │
│                                                     │
├─────────────────────────────────────────────────────┤
│ 🔐 encrypted    YubiKey available       Ctrl+Enter │
└─────────────────────────────────────────────────────┘
```

The important difference from a conventional chat program is that those message bubbles are **rendered from ciphertext on demand**.

When opening Alice:

```text
load last N Signal ciphertext messages
          ↓
select SGPG messages
          ↓
decrypt each in memory
          ↓
render bubbles
```

Close the conversation:

```text
plaintext objects discarded
UI widgets cleared
```

No local chat DB.

## Avoiding repeated YubiKey prompts

One concern is decrypting the last 20 messages.

Fortunately, your OpenPGP card PIN caching through `gpg-agent` means we don't necessarily need twenty separate PIN prompts. We can feed ciphertext to GPG operations while the card/session is active.

The UI could show:

```text
Decrypting conversation…
████████████████ 12/12
```

Then render all twelve messages together.

And because your two YubiKeys contain cloned encryption subkeys, we can add a helper:

```text
sgpg card learn
```

which runs the card relearning operation you already discovered:

```bash
gpg-connect-agent \
  "SCD SERIALNO" \
  "SCD LEARN --force" \
  /bye
```

So swapping to the backup card doesn't require remembering the raw command.

## Plaintext memory hygiene

Python cannot give us perfect memory erasure guarantees.

That's worth stating explicitly.

We can prevent **intentional persistence**, but CPython may make copies of immutable strings/bytes internally, and the OS may swap memory.

Therefore phase two should include hardening:

```text
Avoid Python str where practical for plaintext
Use bytearray for transient buffers
Explicitly overwrite mutable buffers
Disable core dumps
Avoid application logs containing content
Never write exception payloads containing plaintext
Never put message text into argv
Never put plaintext into environment variables
Never automatically copy to clipboard
```

We could also investigate `mlock()` for sensitive buffers on supported systems, though Python makes comprehensive guarantees difficult.

The threat model is therefore:

> Excellent protection against someone stealing an inactive computer and reading historical messages from storage.

Not:

> Absolute protection against an attacker with root access while the application and YubiKey are actively decrypting messages.

## Disk storage

We should distinguish **metadata** from **content**.

Safe to persist:

```text
Signal UUID
Signal phone number
nickname
GPG fingerprint
last-seen Signal timestamp
Signal message IDs
whether message appears SGPG encrypted
```

Do not persist:

```text
decrypted text
decrypted attachments
GPG passphrases/PINs
temporary plaintext
rendered conversation caches
```

I'd probably use SQLite for metadata because it makes indexing message IDs and timestamps much easier.

But:

```text
messages.body
```

does **not exist** in our schema.

The actual ciphertext already exists in Signal/signal-cli's storage.

## Attachments

Not version 1.

Eventually:

```text
sgpg send alice --file document.pdf
```

would encrypt the attachment itself using GPG before giving it to Signal:

```text
document.pdf
   ↓
gpg
   ↓
document.pdf.pgp
   ↓
Signal attachment
```

Decrypt into memory where feasible, or require the user to explicitly choose an output destination.

But text-only first keeps the threat model understandable.

## Signing

Default:

```text
encrypt only
```

Optional:

```text
Ctrl+S   toggle signed
```

or:

```bash
sgpg send --sign alice
```

The UI could show:

```text
🔐 Encrypted
```

versus:

```text
🔐 Encrypted  ✓ Signed by you
```

Receiving:

```text
🔐 Decrypted
✓ Signature: Alice (verified fingerprint)
```

This keeps durable OpenPGP signatures an explicit decision.

## Suggested project structure

```text
sgpg/
├── pyproject.toml
├── README.md
├── src/
│   └── sgpg/
│       ├── __main__.py
│       ├── cli.py
│       ├── app.py
│       │
│       ├── crypto/
│       │   ├── gpg.py
│       │   ├── status.py
│       │   └── card.py
│       │
│       ├── signal/
│       │   ├── client.py
│       │   ├── rpc.py
│       │   └── messages.py
│       │
│       ├── contacts/
│       │   ├── store.py
│       │   └── resolver.py
│       │
│       ├── protocol/
│       │   └── envelope.py
│       │
│       └── tui/
│           ├── app.py
│           ├── conversation.py
│           ├── composer.py
│           └── contacts.py
└── tests/
    ├── test_envelope.py
    ├── test_contacts.py
    ├── test_gpg.py
    └── test_signal_rpc.py
```

Crucially, `crypto/gpg.py` is **not a crypto implementation**. It's a disciplined subprocess adapter around the system `gpg`.

## Build phases

I would implement it in this order:

1. **GPG adapter**

   * enumerate fingerprints
   * inspect encryption capabilities
   * encrypt bytes
   * decrypt bytes
   * encrypt-to-self
   * parse `--status-fd`
   * YubiKey/card detection

2. **Signal adapter**

   * connect to `signal-cli` JSON-RPC
   * list/send/receive
   * parse incoming notifications
   * handle sync messages so your sent messages appear correctly

3. **Protocol + contacts**

   * `SGPG/1` envelope
   * fingerprint mappings
   * contact validation
   * GPG-backed key lookup

4. **Headless CLI**

   * `send`
   * `read`
   * `inbox`
   * `contact`
   * `doctor`

5. **Security tests**

   * ensure plaintext is never written to temp files
   * inspect subprocess argv
   * inspect logs
   * failure-path testing
   * malformed ciphertext
   * missing YubiKey
   * wrong YubiKey
   * revoked/expired recipient keys

6. **Textual chat UI**

   * contact sidebar
   * conversation view
   * multi-line composer
   * decrypt-last-N
   * YubiKey state indicator
   * encryption/signature badges

7. **Attachments/hardening**

   * encrypted attachments
   * core-dump restrictions
   * memory-buffer cleanup
   * optional screen clearing
   * backup-card relearn command

### One feature I'd add from day one

A command like:

```bash
sgpg doctor
```

should report:

```text
✓ gpg found: 2.x
✓ signal-cli found
✓ Signal daemon reachable

Identity:
✓ EBAAD74D6C1534378C0066089A1D947AAB60EEE7

YubiKey:
✓ OpenPGP card detected
✓ signing subkey available
✓ encryption subkey available

Contacts:
✓ 4 contacts
! 1 contact has expired encryption key

Plaintext persistence:
✓ debug logging disabled
✓ core dumps disabled
```

For something whose entire purpose is protecting message history, being able to see **“is my security configuration actually working?”** is unusually valuable.

This gives us a good architecture: **Signal owns transport, GPG owns identity/keys/crypto, YubiKey owns private operations, and our Python program owns only orchestration and UI.**

[1]: https://gnupg.org/documentation/manuals/gnupg26/gpg.1.html?utm_source=chatgpt.com "GPG(1)"
[2]: https://github.com/AsamK/signal-cli/blob/master/man/signal-cli-jsonrpc.5.adoc?utm_source=chatgpt.com "signal-cli/man/signal-cli-jsonrpc.5.adoc at master · AsamK/signal-cli · GitHub"
[3]: https://gnupg.org/documentation/manuals/gnupg/GPG-Configuration-Options.html?utm_source=chatgpt.com "GPG Configuration Options (Using the GNU Privacy Guard)"
[4]: https://github.com/Textualize/textual/blob/main/docs/getting_started.md?utm_source=chatgpt.com "textual/docs/getting_started.md at main · Textualize/textual · GitHub"

