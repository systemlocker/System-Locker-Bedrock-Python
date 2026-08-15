"""One authenticated session: rotating token, heartbeat thread, tamper check."""

from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING, Callable

from .errors import BedrockError, ErrorKind
from .verify import generate_challenge

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .client import Client

CLOCK_JUMP_TOLERANCE_SECONDS = 2.0


class HeartbeatFailure:
    """Delivered to the failure hook exactly once per session."""

    __slots__ = ("error", "response", "completed_heartbeats")

    def __init__(self, error: BedrockError, response=None, completed_heartbeats: int = 0) -> None:
        self.error = error
        self.response = response
        self.completed_heartbeats = completed_heartbeats


class BedrockSession:
    """Owns the heartbeat thread; started by the Client when configured."""

    def __init__(self, client: "Client", token: str, hook: Callable[[HeartbeatFailure], None] | None) -> None:
        self._client = client
        self._token = token
        self._hook = hook
        self._lock = threading.Lock()
        self._request_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._alive = True
        self._completed = 0

    # ── lifecycle ──────────────────────────────────────────────────

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="bedrock-heartbeat", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._alive = False
        self._stop_event.set()

    def wait(self, timeout: float | None = None) -> None:
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    @property
    def alive(self) -> bool:
        return self._alive

    @property
    def completed(self) -> int:
        with self._lock:
            return self._completed

    def set_hook(self, hook: Callable[[HeartbeatFailure], None] | None) -> None:
        self._hook = hook

    # ── failure handling ───────────────────────────────────────────

    def fail(self, error: BedrockError, response=None) -> None:
        was_alive = self._alive
        self.stop()
        self._alive = False
        if not was_alive:
            return
        hook = self._hook
        if hook is not None:
            try:
                hook(HeartbeatFailure(error, response, self.completed))
            except Exception:
                pass  # a throwing user hook must not break the machinery

    # ── heartbeat ──────────────────────────────────────────────────

    def heartbeat(self, request_invisible_folder_token: bool = False):
        with self._request_lock:
            return self._heartbeat_once(request_invisible_folder_token)

    def _heartbeat_once(self, request_invisible_folder_token: bool):
        if not self._alive:
            raise BedrockError(ErrorKind.SESSION_TERMINATED, "Bedrock session is not active.")

        challenge = generate_challenge()
        form: dict[str, str] = {
            "session_token": self._token,
            "system": self._client.config.system_id,
            "challenge": challenge,
        }
        if request_invisible_folder_token:
            form["init-if"] = "true"

        url = self._client.endpoint(self._client.config.base_url, "/auth/bedrock/beat")
        http_response = self._client.http.post_form(url, form, self._client.signed_headers())
        # A transport failure may mean the server committed the rotation but
        # the response was lost. Repeat the exact token/challenge once so
        # Bedrock can return its cached signed response.
        if http_response.error:
            http_response = self._client.http.post_form(url, form, self._client.signed_headers())

        if not http_response.ok():
            message = (
                f"Bedrock heartbeat transport failed: {http_response.error}"
                if http_response.error
                else f"Bedrock heartbeat returned HTTP {http_response.status}."
            )
            error = BedrockError(ErrorKind.TRANSPORT, message)
            self.fail(error)
            raise error

        try:
            response = self._client.verify_signed(http_response, challenge)
        except BedrockError as error:
            if error.kind is ErrorKind.UNSIGNED_RESPONSE:
                try:
                    response = self._client.parse_unsigned(http_response, challenge)
                except BedrockError as revocation_error:
                    self.fail(revocation_error)
                    raise revocation_error from None
            else:
                self.fail(error)
                raise

        if response.code != "OK" or not response.authed or response.session_token is None:
            error = BedrockError(
                ErrorKind.SESSION_TERMINATED,
                response.termination_message or response.human_response,
            )
            self.fail(error, response)
            return response
        if not response.session_token.startswith("BRF_"):
            error = BedrockError(ErrorKind.INVALID_PAYLOAD, "Bedrock heartbeat returned an invalid rotated token format.")
            self.fail(error)
            raise error

        with self._lock:
            self._token = response.session_token
            self._completed += 1
        return response

    # ── background loop ────────────────────────────────────────────

    def _run(self) -> None:
        previous_monotonic = time.monotonic()
        previous_wall = time.time()

        while not self._stop_event.wait(self._client.config.beat_rate_seconds):
            monotonic = time.monotonic()
            wall = time.time()
            monotonic_elapsed = monotonic - previous_monotonic
            wall_elapsed = wall - previous_wall
            previous_monotonic = monotonic
            previous_wall = wall
            if abs(monotonic_elapsed - wall_elapsed) > CLOCK_JUMP_TOLERANCE_SECONDS:
                self.fail(BedrockError(ErrorKind.LOCAL_FAILURE, "Local clock changed unexpectedly during a Bedrock session."))
                return

            try:
                self.heartbeat()
            except BedrockError:
                return  # fail() already ran
            if not self._alive:
                return
