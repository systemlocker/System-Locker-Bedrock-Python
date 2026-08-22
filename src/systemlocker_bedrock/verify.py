"""The Bedrock verification pipeline: headers, encoding, signature, payload."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import secrets
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .config import Config
from .errors import BedrockError, ErrorKind
from .response import Response, expected_authenticated, expected_error, expected_failure, response_code_is_known
from .transport import HTTPResponse

PROTOCOL_VERSION = "bedrock-v1"
SIGNATURE_BYTES = 64
PUBLIC_KEY_BYTES = 32
CHALLENGE_BYTES = 64
MAX_TRANSPORT_BYTES = 1024 * 1024

_B64URL_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def generate_challenge() -> str:
    """Fresh 64-byte base64url challenge from the system CSPRNG."""
    return base64.urlsafe_b64encode(secrets.token_bytes(CHALLENGE_BYTES)).decode("ascii").rstrip("=")


def sha256_hex(value: str) -> str:
    """Lowercase-hex SHA-256 of a string (identity hashes)."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def base64_url_decode(value: str) -> bytes:
    if not value or len(value) > MAX_TRANSPORT_BYTES or len(value) % 4 == 1:
        raise BedrockError(ErrorKind.INVALID_PAYLOAD, "Invalid base64url length.")
    if not _B64URL_ALPHABET.issuperset(value):
        raise BedrockError(ErrorKind.INVALID_PAYLOAD, "Invalid base64url character.")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError) as error:
        raise BedrockError(ErrorKind.INVALID_PAYLOAD, "Invalid base64url value.") from error
    if base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value:
        raise BedrockError(ErrorKind.INVALID_PAYLOAD, "Invalid base64url value.")
    return decoded


def verify_signed_response(config: Config, http_response: HTTPResponse, expected_challenge: str, now: float | None = None) -> Response:
    """The verification pipeline in the specification's exact order."""
    if now is None:
        now = time.time()

    if http_response.header("x-bedrock-protocol") != PROTOCOL_VERSION or http_response.header("x-bedrock-signed") == "false":
        raise BedrockError(ErrorKind.UNSIGNED_RESPONSE, "Bedrock response is missing its signed transport headers.")

    try:
        signed_bytes = base64_url_decode(http_response.body.decode("latin-1"))
    except BedrockError:
        raise
    if len(signed_bytes) <= SIGNATURE_BYTES:
        raise BedrockError(ErrorKind.INVALID_PAYLOAD, "Bedrock signed response has an invalid encoding or length.")

    try:
        public_key = base64_url_decode(config.signing_public_key)
    except BedrockError as error:
        raise BedrockError(ErrorKind.CONFIGURATION, "Pinned Bedrock public key is not a raw 32-byte Ed25519 key.") from error
    if len(public_key) != PUBLIC_KEY_BYTES:
        raise BedrockError(ErrorKind.CONFIGURATION, "Pinned Bedrock public key is not a raw 32-byte Ed25519 key.")

    signature = signed_bytes[:SIGNATURE_BYTES]
    message = signed_bytes[SIGNATURE_BYTES:]
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except Exception as error:
        raise BedrockError(ErrorKind.INVALID_SIGNATURE, "Bedrock response signature verification failed.") from error

    return parse_payload(config, message.decode("utf-8"), expected_challenge, now, http_response)


def parse_unsigned_revocation(config: Config, http_response: HTTPResponse, expected_challenge: str, now: float | None = None) -> Response:
    """The single permitted unsigned response: denial-only."""
    if now is None:
        now = time.time()
    if http_response.header("x-bedrock-signed") != "false" or http_response.header("x-bedrock-protocol") != PROTOCOL_VERSION:
        raise BedrockError(ErrorKind.UNSIGNED_RESPONSE, "Bedrock returned an unauthenticated response.")
    parsed = parse_payload(config, http_response.body.decode("utf-8"), expected_challenge, now)
    if parsed.code != "SIGNING_KEY_REVOKED" or parsed.termination_message is None:
        raise BedrockError(ErrorKind.UNSIGNED_RESPONSE, "Unsigned Bedrock response is diagnostic only and cannot be trusted.")
    return parsed


def parse_payload(config: Config, json_text: str, expected_challenge: str, now: float, http_response: HTTPResponse | None = None) -> Response:
    try:
        payload = json.loads(json_text)
    except ValueError as error:
        raise BedrockError(ErrorKind.INVALID_PAYLOAD, "Bedrock response JSON is invalid.") from error
    if not isinstance(payload, dict):
        raise BedrockError(ErrorKind.INVALID_PAYLOAD, "Bedrock payload is not a JSON object.")

    def require_string(name: str) -> str:
        value = payload.get(name)
        if not isinstance(value, str):
            raise BedrockError(ErrorKind.INVALID_PAYLOAD, f"Bedrock field '{name}' is missing or has the wrong type.")
        return value

    def require_bool(name: str) -> bool:
        value = payload.get(name)
        if not isinstance(value, bool):
            raise BedrockError(ErrorKind.INVALID_PAYLOAD, f"Bedrock field '{name}' is missing or has the wrong type.")
        return value

    def optional_string(name: str) -> str | None:
        value = payload.get(name)
        if value is None:
            return None
        if not isinstance(value, str):
            raise BedrockError(ErrorKind.INVALID_PAYLOAD, f"Bedrock field '{name}' has the wrong type.")
        return value

    response = Response()
    response.protocol_version = require_string("protocol_version")
    response.key_id = require_string("kid") if http_response is not None else optional_string("kid")
    response.system = require_string("system")
    response.code = require_string("response_code")
    response.human_response = require_string("human_response")
    response.is_error = require_bool("is_error")
    response.is_failure = require_bool("is_failure")
    response.authed = require_bool("authed")
    response.human_time = require_string("human_time")
    response.challenge = require_string("challenge")

    server_time = payload.get("server_time")
    if not isinstance(server_time, int) or isinstance(server_time, bool):
        raise BedrockError(ErrorKind.INVALID_PAYLOAD, "Bedrock field 'server_time' is missing or has the wrong type.")
    response.server_time = server_time

    response.session_token = optional_string("session_token")
    response.license_key_hash = optional_string("license_key_hash")
    response.username_hash = optional_string("username_hash")
    response.termination_message = optional_string("termination_message")
    response.sso_url = optional_string("sso_url")
    response.invisible_folder_token = optional_string("invisible_folder_token")

    variables = payload.get("variables")
    if variables is not None:
        if not isinstance(variables, dict):
            raise BedrockError(ErrorKind.INVALID_PAYLOAD, "Bedrock field 'variables' has the wrong type.")
        for name, value in variables.items():
            if isinstance(value, str):
                response.variables[name] = value
            elif value is False:
                response.variables[name] = None
            else:
                raise BedrockError(ErrorKind.INVALID_PAYLOAD, "Bedrock variable has the wrong type.")

    if response.protocol_version != PROTOCOL_VERSION:
        raise BedrockError(ErrorKind.INVALID_PAYLOAD, "Unsupported Bedrock protocol version.")
    if http_response is not None:
        if response.key_id is None or http_response.header("x-bedrock-key-id") != response.key_id:
            raise BedrockError(ErrorKind.INVALID_PAYLOAD, "Bedrock response signing key ID is missing or inconsistent.")
        if config.signing_key_id and response.key_id != config.signing_key_id:
            raise BedrockError(ErrorKind.INVALID_PAYLOAD, "Bedrock response signing key ID does not match the configured pin.")
    if not response_code_is_known(response.code):
        raise BedrockError(ErrorKind.INVALID_PAYLOAD, "Bedrock response contains an unknown response code.")
    if (
        response.authed != expected_authenticated(response.code)
        or response.is_error != expected_error(response.code)
        or response.is_failure != expected_failure(response.code)
    ):
        raise BedrockError(ErrorKind.INVALID_PAYLOAD, "Bedrock response flags contradict its response code.")
    if response.system != config.system_id:
        raise BedrockError(ErrorKind.INVALID_PAYLOAD, "Bedrock response is bound to a different system.")
    if response.challenge != expected_challenge:
        raise BedrockError(ErrorKind.INVALID_PAYLOAD, "Bedrock response challenge does not match the request.")
    if abs(response.server_time - int(now)) > config.max_server_clock_skew_seconds:
        raise BedrockError(ErrorKind.FRESHNESS_VIOLATION, "Bedrock response server time is outside the configured freshness window.")
    return response
