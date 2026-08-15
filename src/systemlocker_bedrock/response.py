"""Response code table and flag-consistency rules."""

from __future__ import annotations

RESPONSE_CODES = frozenset(
    {
        "OK", "OUTDATED", "MISSING_FIELD", "INVALID_REQUEST", "INVALID_SYSTEM",
        "INVALID_CREDENTIALS", "USER_NOT_VERIFIED", "INVALID_KEY", "KEY_FROZEN",
        "HWID_BANNED", "HWID_MISMATCH", "SPOOF_SUSPECTED", "SYSTEM_PAUSED",
        "PLAN_INACTIVE", "PRODUCTION_AUTH_UNAVAILABLE", "USER_LIMIT_REACHED",
        "EXPIRED_KEY", "PROGRAM_DIGEST_MISMATCH", "INVALID_BEATRATE",
        "NO_ACTIVE_SIGNING_KEY", "INVALID_SESSION", "SESSION_TERMINATED",
        "STALE_SESSION", "HEARTBEAT_TOO_EARLY", "HEARTBEAT_VARIANCE_EXCEEDED",
        "SIGNING_KEY_REVOKED", "CONCURRENT_HEARTBEAT", "INTERNAL_ERROR",
    }
)

FAILURE_CODES = frozenset(
    {
        "MISSING_FIELD", "INVALID_REQUEST", "INVALID_SYSTEM", "SYSTEM_PAUSED",
        "PLAN_INACTIVE", "PRODUCTION_AUTH_UNAVAILABLE", "PROGRAM_DIGEST_MISMATCH",
        "INVALID_BEATRATE", "NO_ACTIVE_SIGNING_KEY", "INTERNAL_ERROR",
    }
)


def response_code_is_known(code: str) -> bool:
    return code in RESPONSE_CODES


def expected_authenticated(code: str) -> bool:
    return code in {"OK", "OUTDATED"}


def expected_failure(code: str) -> bool:
    return code in FAILURE_CODES


def expected_error(code: str) -> bool:
    return code != "OK" and code not in FAILURE_CODES


class Response:
    """A fully verified Bedrock response payload."""

    __slots__ = (
        "code", "human_response", "is_error", "is_failure", "authed",
        "protocol_version", "key_id", "system", "challenge", "server_time", "human_time",
        "session_token", "license_key_hash", "username_hash",
        "termination_message", "invisible_folder_token", "variables",
    )

    def __init__(self) -> None:
        self.code: str = ""
        self.human_response: str = ""
        self.is_error: bool = False
        self.is_failure: bool = False
        self.authed: bool = False
        self.protocol_version: str = ""
        self.key_id: str | None = None
        self.system: str = ""
        self.challenge: str = ""
        self.server_time: int = 0
        self.human_time: str = ""
        self.session_token: str | None = None
        self.license_key_hash: str | None = None
        self.username_hash: str | None = None
        self.termination_message: str | None = None
        self.invisible_folder_token: str | None = None
        #: variable name -> value, or None when the server reports it absent
        self.variables: dict[str, str | None] = {}

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Response(code={self.code!r}, authed={self.authed!r})"
