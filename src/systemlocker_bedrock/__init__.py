"""Official System Locker Bedrock client for Python.

Bedrock targets software distributed to untrusted machines: every server
response is Ed25519-signed and verified against a pinned public key before
parsing, sessions rotate tokens on every heartbeat, and each request carries
a fresh cryptographic challenge.
"""

from .client import AuthenticationResult, Client
from .config import Config, default_config, validate_config
from .errors import BedrockError, ErrorKind
from .response import RESPONSE_CODES, Response
from .session import BedrockSession, HeartbeatFailure
from .transport import HTTPClient, HTTPResponse
from .verify import (
    generate_challenge,
    parse_unsigned_revocation,
    sha256_hex,
    verify_signed_response,
)

__version__ = "0.1.0"

__all__ = [
    "AuthenticationResult",
    "BedrockError",
    "BedrockSession",
    "Client",
    "Config",
    "ErrorKind",
    "HTTPClient",
    "HTTPResponse",
    "HeartbeatFailure",
    "RESPONSE_CODES",
    "Response",
    "default_config",
    "generate_challenge",
    "parse_unsigned_revocation",
    "sha256_hex",
    "validate_config",
    "verify_signed_response",
]
