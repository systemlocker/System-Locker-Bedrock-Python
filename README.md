# System Locker Bedrock — Python

Official Python client for **System Locker Bedrock**, the license-verification
protocol for software distributed to **untrusted machines**. Every server
response is Ed25519-signed and verified against a pinned public key before
parsing, sessions rotate tokens on every heartbeat, and each request carries
a fresh cryptographic challenge — replay attacks and forged responses are
infeasible even for an attacker who fully controls the network.

If your code runs on a machine you control, look at the System Locker Simple
client instead.

## Install

```sh
pip install systemlocker-bedrock
```

One dependency: `cryptography`. Python 3.10+. Fully typed.

## Quickstart

```python
from systemlocker_bedrock import Client, default_config

config = default_config()
config.system_id = "abcdefghijklmnopqrst"             # from the dashboard
config.signing_public_key = "…base64url Ed25519 key…" # from the dashboard
config.version = "1.0.0"

client = Client(config)
client.on_heartbeat_failure(lambda failure: save_and_exit(failure.error.message))

result = client.authenticate_with_key(
    "SL-XXXX-XXXX-XXXX",
    request_invisible_folder_token=True,
    variables=["tier"],
)
if not result.session_started:
    raise SystemExit(1)

# …your protected application logic; heartbeats run in a daemon thread…
client.shutdown()
```

## What the client enforces for you

- **Signed responses only.** The Ed25519 signature is verified against the
  pinned key _before_ any parsing; tampered payloads never reach your code.
- **Challenge echoes.** Every init/beat carries a fresh 86-character
  `secrets`-generated challenge that the server must echo exactly.
- **Freshness.** `server_time` must be within `max_server_clock_skew_seconds`
  (default 120) of the local clock.
- **Identity binding.** The response's `license_key_hash`/`username_hash`
  must equal the locally computed SHA-256 of the submitted credential.
- **Token rotation.** Init tokens start with `BRK_`, every heartbeat rotates
  to a `BRF_` token; a lost heartbeat response is retried once, idempotently.
- **Denial-only unsigned responses.** Exactly one unsigned response is ever
  accepted: a `SIGNING_KEY_REVOKED` termination, which only ends the session.

Failures raise `BedrockError` whose `kind` (`ErrorKind.INVALID_SIGNATURE`,
`ErrorKind.FRESHNESS_VIOLATION`, …) distinguishes infrastructure problems
from attacks from legitimate denials.

## Heartbeats

With `automatic_heartbeats=True` (the default) a daemon thread beats every
`beat_rate_seconds` (25–3600). When it fails, your `on_heartbeat_failure`
hook fires once and the session is dead. Disable it and call
`client.heartbeat_now()` yourself for manual control.

## Invisible Folder file delivery

```python
folder = client.invisible_folder()
result = folder.download_if_new("app-assets-v1", last_revision, "assets.zip")
if result.downloaded:
    last_revision = result.revision  # persist this
```

`download` (bytes), `download_to_file` (disk, unencrypted), `metadata`, and
`download_if_new` (revision-checked) are available. Tokens live in memory
only and clear on `shutdown()`.

## Google SSO (account authentication)

Accounts created through Google sign-in have no local password on the
server. A `username`/`password` authentication for such an account is
answered with a signed `GOOGLE_SSO_REQUIRED` denial whose payload carries
`sso_url` — the portal where the user completes Google sign-in and receives
a system-specific password (valid 180 days) to use as their account
password. There is no callback; the user transcribes the generated password
into your login form and you simply retry.

```python
result = client.authenticate_with_password(username, password)
if result.response.code == "GOOGLE_SSO_REQUIRED":
    # The denial's URL is authoritative; open it in the default browser.
    portal = result.response.sso_url or client.google_sso_url()
    if not open_url(portal):
        print(f"Finish Google sign-in at: {portal}")  # headless fallback
```

You can also start the flow before any denial: `client.begin_google_sso()`
(or `begin_google_sso(system_id)`) opens the portal and returns an
`(url, opened)` tuple.

## Device identifiers (HWID)

The library derives a hardware ID by default; set `config.hwid = "1"` only to
explicitly disable device locking.

```python
from systemlocker_bedrock.hwid import device_hwid

config.hwid = device_hwid()
```

Derives a stable identifier from the machine GUID, hardware UUID, CPU id,
and MAC (Windows and Linux). Passing your own stable value works just as
well — and avoids hardware-enumeration quirks entirely.

## Security

See [SECURITY.md](SECURITY.md). Report vulnerabilities privately through the
System Locker support channels, not via public issues.
