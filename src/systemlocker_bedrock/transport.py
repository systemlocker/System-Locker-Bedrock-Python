"""Transport layer: injectable HTTP client plus a urllib-based default."""

from __future__ import annotations

import urllib.error
import urllib.request
from typing import Mapping, Sequence


class HTTPResponse:
    """Transport-neutral result of one exchange. Header keys are lowercase."""

    __slots__ = ("status", "body", "headers", "error")

    def __init__(self, status: int = 0, body: bytes = b"", headers: Mapping[str, str] | None = None, error: str = "") -> None:
        self.status = status
        self.body = body
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.error = error

    def ok(self) -> bool:
        return not self.error and 200 <= self.status < 300

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")


class HTTPClient:
    """Override ``post_form``/``get`` (or the whole class) to inject a fake."""

    def __init__(self, timeout_seconds: float = 15.0, user_agent: str = "systemlocker-bedrock-python/0.1") -> None:
        self.timeout_seconds = timeout_seconds
        self.user_agent = user_agent

    def post_form(self, url: str, fields: Mapping[str, str | Sequence[str]], headers: Mapping[str, str] | None = None) -> HTTPResponse:
        return self._execute("POST", url, form=fields, headers=headers)

    def get(self, url: str, headers: Mapping[str, str] | None = None) -> HTTPResponse:
        return self._execute("GET", url, headers=headers)

    def _encode_form(self, fields: Mapping[str, str | Sequence[str]]) -> bytes:
        from urllib.parse import urlencode
        pairs: list[tuple[str, str]] = []
        for key, value in fields.items():
            if isinstance(value, str):
                pairs.append((key, value))
            else:
                pairs.extend((key, item) for item in value)
        return urlencode(pairs).encode("utf-8")

    def _execute(self, method: str, url: str, form: Mapping[str, str | Sequence[str]] | None = None, headers: Mapping[str, str] | None = None) -> HTTPResponse:
        request_headers = {"User-Agent": self.user_agent}
        for name, value in (headers or {}).items():
            request_headers[name] = value
        data = None
        if form is not None:
            data = self._encode_form(form)
            request_headers["Content-Type"] = "application/x-www-form-urlencoded"

        request = urllib.request.Request(url, data=data, headers=request_headers, method=method)
        opener = urllib.request.build_opener(_NoRedirect())
        try:
            with opener.open(request, timeout=self.timeout_seconds) as result:
                body = _read_bounded(result)
                return HTTPResponse(status=result.status, body=body, headers=dict(result.headers))
        except urllib.error.HTTPError as http_error:
            try:
                body = _read_bounded(http_error)
            except Exception:  # pragma: no cover - defensive
                body = b""
            return HTTPResponse(status=http_error.code, body=body, headers=dict(http_error.headers or {}))
        except Exception as error:  # urllib raises several exception types
            return HTTPResponse(error=str(error))


_MAX_RESPONSE_BYTES = 1024 * 1024


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


def _read_bounded(stream: object) -> bytes:
    headers = getattr(stream, "headers", None)
    content_length = headers.get("Content-Length") if headers is not None else None
    if content_length is not None and int(content_length) > _MAX_RESPONSE_BYTES:
        raise ValueError("response body exceeds 1 MiB limit")
    body = stream.read(_MAX_RESPONSE_BYTES + 1)  # type: ignore[attr-defined]
    if len(body) > _MAX_RESPONSE_BYTES:
        raise ValueError("response body exceeds 1 MiB limit")
    return body
