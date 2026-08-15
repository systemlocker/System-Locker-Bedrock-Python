"""Error kinds and the exception type, identical across official clients."""

from __future__ import annotations

from enum import Enum


class ErrorKind(str, Enum):
    CONFIGURATION = "Configuration"
    TRANSPORT = "Transport"
    UNSIGNED_RESPONSE = "UnsignedResponse"
    INVALID_SIGNATURE = "InvalidSignature"
    INVALID_PAYLOAD = "InvalidPayload"
    FRESHNESS_VIOLATION = "FreshnessViolation"
    SESSION_TERMINATED = "SessionTerminated"
    LOCAL_FAILURE = "LocalFailure"


class BedrockError(Exception):
    """Every client operation raises this; ``kind`` categorizes it."""

    def __init__(self, kind: ErrorKind, message: str) -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"BedrockError({self.kind.value!r}, {self.message!r})"
