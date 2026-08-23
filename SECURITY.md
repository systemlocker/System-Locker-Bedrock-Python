# Security Policy

## Threat model

Bedrock assumes the client machine is **untrusted**: an attacker can read
memory, intercept traffic, and replay captured messages. The controls that
matter therefore live in the protocol, not in obfuscation:

- Every response is Ed25519-signed and verified against the pinned
  `signing_public_key` **before parsing**. Nothing unsigned is ever trusted —
  with one denial-only exception (`SIGNING_KEY_REVOKED`), which can only end
  a session.
- Per-request 64-byte challenges from `secrets` must be echoed exactly,
  binding each response to one request and defeating replay.
- `server_time` freshness, system/identity echoes, and token rotation
  (`BRK_`/`BRF_`) are all verified on every response.
- All client randomness comes from `secrets.token_bytes`.

## Accepted limitations

- Python strings cannot be wiped deterministically; credentials remain in
  garbage-collected memory until collection.
- Debugger-detection and code self-integrity checks from the C++ client do
  not meaningfully port to an interpreted runtime and are not implemented.
  The signature verification remains the real control.
- Downloads to disk are written unencrypted (parity with the C++ client);
  protect them at the application layer if needed.
- TLS certificate validation is always on; TLS public-key pinning is not
  implemented (the response signature already provides the
  man-in-the-middle defense).

## SL-HWID module

The default threshold HWID module makes copied state and casual spoofing
harder by requiring a stored enrollment plus enough current factors. Our
objective is to reduce HWID churn from minor hardware changes, without
reducing the strength of HWID as a locking mechanism. The key itself is never
persisted.

## Reporting a vulnerability

Report privately through the System Locker developer dashboard. Do not open
public issues for security problems.
