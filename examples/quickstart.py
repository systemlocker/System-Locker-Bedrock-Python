"""Smallest working Bedrock integration."""

from __future__ import annotations

from systemlocker_bedrock import Client, default_config
from systemlocker_bedrock.hwid import device_hwid

try:
    hwid = device_hwid()
except RuntimeError:
    hwid = "my-own-stable-identifier"  # developer-supplied fallback

config = default_config()
config.system_id = "abcdefghijklmnopqrst"            # from the dashboard
config.signing_public_key = "…base64url Ed25519 key…"  # from the dashboard
config.hwid = hwid
config.version = "1.0.0"

client = Client(config)
client.on_heartbeat_failure(lambda failure: print("session ended:", failure.error.message))

result = client.authenticate_with_key(
    "SL-XXXX-XXXX-XXXX",
    request_invisible_folder_token=True,
    variables=["tier"],
)
if not result.session_started:
    print("rejected:", result.response.human_response)
    raise SystemExit(1)

print("authenticated; heartbeating automatically")
# …your protected application logic…
client.shutdown()
