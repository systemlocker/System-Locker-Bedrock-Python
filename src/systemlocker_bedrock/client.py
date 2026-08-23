"""The Bedrock Client."""

from __future__ import annotations

import threading
from typing import Callable

from .config import Config, default_config, default_now, validate_config
from .errors import BedrockError, ErrorKind
from .invisible_folder import InvisibleFolder
from .response import Response
from .session import BedrockSession, HeartbeatFailure
from .sso import begin_google_sso, google_sso_url
from .transport import HTTPClient
from .verify import generate_challenge, parse_unsigned_revocation, sha256_hex, verify_signed_response


class AuthenticationResult:
    """Outcome of an authenticate call."""

    __slots__ = ("response", "session_started")

    def __init__(self, response: Response, session_started: bool) -> None:
        self.response = response
        self.session_started = session_started


class Client:
    """Bedrock client for one system.

    Construct, call :meth:`authenticate_with_key` or
    :meth:`authenticate_with_password` once, then let the background
    heartbeat keep the session alive (or drive :meth:`heartbeat_now` with
    ``automatic_heartbeats=False``). Thread-safe.
    """

    def __init__(self, config: Config | None = None, http: HTTPClient | None = None, now: Callable[[], float] | None = None) -> None:
        self.config = config or default_config()
        if not self.config.hwid and self.config.hwid_mode != "sl-hwid":
            try:
                from .hwid import device_hwid
                self.config.hwid = device_hwid()
            except Exception as error:
                raise BedrockError(ErrorKind.CONFIGURATION, f'Could not derive the default hardware ID: {error}. Supply a custom HWID or use "1" to disable device checks.') from error
        validate_config(self.config)
        self.http = http or HTTPClient(
            timeout_seconds=self.config.request_timeout_seconds,
            user_agent=self.config.user_agent,
        )
        self._now = now or default_now
        self._session: BedrockSession | None = None
        self._failure_hook: Callable[[HeartbeatFailure], None] | None = None
        self._state_lock = threading.Lock()
        self._invisible_folder = InvisibleFolder(self)
        self._ss_sessions: dict[str, object] = {}

    # ── plumbing ───────────────────────────────────────────────────

    def endpoint(self, base_url: str, path: str) -> str:
        return base_url.rstrip("/") + path

    def signed_headers(self) -> dict[str, str]:
        if self.config.signing_key_id:
            return {"X-Bedrock-Key-Id": self.config.signing_key_id}
        return {}

    def verify_signed(self, http_response, challenge: str) -> Response:
        return verify_signed_response(self.config, http_response, challenge, self._now())

    def parse_unsigned(self, http_response, challenge: str) -> Response:
        return parse_unsigned_revocation(self.config, http_response, challenge, self._now())

    # ── authentication ─────────────────────────────────────────────

    def authenticate_with_key(self, license_key: str, *, request_invisible_folder_token: bool = False, variables: list[str] | None = None) -> AuthenticationResult:
        return self._authenticate({"key": license_key}, license_key, True, request_invisible_folder_token, variables)

    def authenticate_with_password(self, username: str, password: str, *, request_invisible_folder_token: bool = False, variables: list[str] | None = None) -> AuthenticationResult:
        return self._authenticate({"username": username, "password": password}, username, False, request_invisible_folder_token, variables)

    # ── Google SSO ────────────────────────────────────────────────

    def google_sso_url(self) -> str:
        """Return the Google SSO portal URL for the configured system."""
        return google_sso_url(self.config.system_id)

    def begin_google_sso(self) -> tuple[str, bool]:
        """Open the Google SSO portal for the configured system.

        See :func:`systemlocker_bedrock.sso.begin_google_sso` for the
        ``(url, opened)`` result contract.
        """
        return begin_google_sso(self.config.system_id)

    def _prepare_secret_sharing(self, identity: str):
        """Recovers the shared device HWID; sessions remain cached per identity."""
        with self._state_lock:
            cached = self._ss_sessions.get(identity)
            if cached is not None:
                return cached
        from .slhwid import Options, prepare as ss_prepare

        try:
            session = ss_prepare(
                Options(
                    store_path=self.config.sl_hwid_store,
                    extra_mandatory=self.config.sl_hwid_extra_mandatory or [],
                )
            )
        except Exception as error:
            raise BedrockError(ErrorKind.LOCAL_FAILURE, f"Secret-sharing HWID unavailable: {error}") from error
        with self._state_lock:
            self._ss_sessions[identity] = session
        return session

    def _authenticate(self, extra_fields: dict[str, str], identity: str, key_authentication: bool, request_if_token: bool, variables: list[str] | None) -> AuthenticationResult:
        challenge = generate_challenge()
        hwid_value = self.config.hwid
        ss_session = None
        if not hwid_value:  # secret_sharing mode: recover or enroll at auth time
            ss_session = self._prepare_secret_sharing(identity)
            hwid_value = ss_session.hwid
        form: dict[str, object] = {
            **extra_fields,
            "system": self.config.system_id,
            "hwid": hwid_value,
            "version": self.config.version,
            "beatrate": str(int(self.config.beat_rate_seconds)),
            "challenge": challenge,
        }
        if self.config.program_digest:
            form["digest"] = self.config.program_digest
        if request_if_token:
            form["init-if"] = "true"
        if variables:
            form["variables[]"] = variables

        http_response = self.http.post_form(
            self.endpoint(self.config.base_url, "/auth/bedrock/init"), form, self.signed_headers()
        )
        if not http_response.ok():
            message = (
                f"Bedrock initialization transport failed: {http_response.error}"
                if http_response.error
                else f"Bedrock initialization returned HTTP {http_response.status}."
            )
            raise BedrockError(ErrorKind.TRANSPORT, message)

        response = self.verify_signed(http_response, challenge)

        authenticated_code = response.code in {"OK", "OUTDATED"}
        if response.authed != authenticated_code:
            raise BedrockError(ErrorKind.INVALID_PAYLOAD, "Bedrock authentication flags contradict the response code.")

        result = AuthenticationResult(response, False)
        if not response.authed:
            if response.variables or response.invisible_folder_token is not None:
                raise BedrockError(ErrorKind.INVALID_PAYLOAD, "A rejected Bedrock initialization returned successful-only data.")
            return result
        if response.session_token is None:
            raise BedrockError(ErrorKind.INVALID_PAYLOAD, "Authenticated Bedrock response did not contain a session token.")
        if not response.session_token.startswith("BRK_"):
            raise BedrockError(ErrorKind.INVALID_PAYLOAD, "Bedrock initialization returned an invalid session token format.")

        identity_hash = sha256_hex(identity)
        response_hash = response.license_key_hash if key_authentication else response.username_hash
        if response_hash != identity_hash:
            raise BedrockError(ErrorKind.INVALID_PAYLOAD, "Bedrock response identity hash does not match the authentication request.")

        # The server accepted this identity on this device: re-center the
        # secret-sharing shares on the hardware observed this launch.
        # Failures are non-fatal — the next launch re-derives.
        if ss_session is not None:
            ss_session.commit()

        with self._state_lock:
            previous = self._session
        if previous is not None:
            previous.stop()
            previous.wait(timeout=self.config.request_timeout_seconds + 5)
        session = BedrockSession(self, response.session_token, self._failure_hook)
        if self.config.automatic_heartbeats:
            session.start()
        with self._state_lock:
            self._session = session

        if response.invisible_folder_token is not None:
            self._invisible_folder.set_token(response.invisible_folder_token)
        result.session_started = True
        return result

    # ── session control ────────────────────────────────────────────

    def heartbeat_now(self, *, request_invisible_folder_token: bool = False) -> Response:
        with self._state_lock:
            session = self._session
        if session is None:
            raise BedrockError(ErrorKind.SESSION_TERMINATED, "No Bedrock session is active.")
        response = session.heartbeat(request_invisible_folder_token)
        if response.authed and response.invisible_folder_token is not None:
            self._invisible_folder.set_token(response.invisible_folder_token)
        return response

    def on_heartbeat_failure(self, hook: Callable[[HeartbeatFailure], None]) -> None:
        with self._state_lock:
            self._failure_hook = hook
            session = self._session
        if session is not None:
            session.set_hook(hook)

    def is_authenticated(self) -> bool:
        with self._state_lock:
            session = self._session
        return session is not None and session.alive

    def heartbeat_count(self) -> int:
        with self._state_lock:
            session = self._session
        return session.completed if session is not None else 0

    def invisible_folder(self) -> InvisibleFolder:
        return self._invisible_folder

    def shutdown(self) -> None:
        with self._state_lock:
            previous = self._session
            self._session = None
        if previous is not None:
            previous.stop()
            previous.wait(timeout=self.config.request_timeout_seconds + 5)
        self._invisible_folder.clear_token()
