"""Client configuration with protocol-exact validation."""

from __future__ import annotations

import base64
import binascii
import re
import time
from dataclasses import dataclass

from .errors import BedrockError, ErrorKind

_SYSTEM_ID_PATTERN = re.compile(r"^[A-Za-z0-9]{20}$")


@dataclass
class Config:
    """Configures a Bedrock Client. Start from :func:`default_config`."""

    system_id: str = ""
    version: str = "bypass"
    hwid: str = ""
    beat_rate_seconds: float = 30.0
    request_timeout_seconds: float = 15.0
    max_server_clock_skew_seconds: int = 120
    base_url: str = "https://systemlocker.net"
    invisible_folder_base_url: str = "https://invisiblefolder.net"
    user_agent: str = "systemlocker-bedrock-python/0.1"
    program_digest: str | None = None
    signing_key_id: str | None = None
    invisible_folder_api_key: str | None = None
    signing_public_key: str = ""
    automatic_heartbeats: bool = True


def default_config() -> Config:
    """Returns a Config with every default filled in."""
    return Config()


def validate_config(config: Config) -> None:
    """Raises a Configuration error on the first violation."""
    if not _SYSTEM_ID_PATTERN.match(config.system_id or ""):
        raise BedrockError(
            ErrorKind.CONFIGURATION,
            "System ID must be exactly 20 alphanumeric characters.",
        )
    if not 25 <= config.beat_rate_seconds <= 3600:
        raise BedrockError(
            ErrorKind.CONFIGURATION,
            "Bedrock heartbeat interval must be from 25 through 3600 seconds.",
        )
    if not (config.base_url or "").startswith("https://"):
        raise BedrockError(ErrorKind.CONFIGURATION, "Bedrock base URL must use HTTPS.")
    if not 0 < config.max_server_clock_skew_seconds <= 3600:
        raise BedrockError(
            ErrorKind.CONFIGURATION,
            "Bedrock clock-skew allowance must be greater than zero and no more than one hour.",
        )
    try:
        decoded = base64.urlsafe_b64decode(config.signing_public_key + "=" * (-len(config.signing_public_key) % 4))
    except (binascii.Error, ValueError):
        decoded = b""
    if not config.signing_public_key or len(decoded) != 32:
        raise BedrockError(
            ErrorKind.CONFIGURATION,
            "The Bedrock public key must decode to exactly 32 bytes.",
        )


def default_now() -> float:
    """Wall-clock time in seconds (swappable in tests)."""
    return time.time()
