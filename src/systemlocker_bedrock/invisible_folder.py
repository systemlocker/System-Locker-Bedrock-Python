"""Invisible Folder file delivery through the authenticated Bedrock session."""

from __future__ import annotations

import json
import re
import threading
from pathlib import Path

from .errors import BedrockError, ErrorKind
from .transport import HTTPResponse

DOWNLOAD_PREFIX = "/a/"
METADATA_PREFIX = "/api/v1/files/"
METADATA_SUFFIX = "/metadata"
REVISIONS_KEY = "__revisions"

_REFERENCE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{4,128}$")

FILE_STRING_FIELDS = ("id", "reference_id", "name", "mime_type", "uploaded_at")


def valid_reference_id(reference_id: str) -> bool:
    return bool(_REFERENCE_ID_PATTERN.match(reference_id or ""))


def percent_encode(value: str) -> str:
    from urllib.parse import quote
    return quote(value, safe="-_.")


class InvisibleFolderFile:
    __slots__ = ("id", "reference_id", "name", "mime_type", "size", "downloads", "uploaded_at", "permission_type_id")

    def __init__(self, **fields) -> None:
        for slot in self.__slots__:
            setattr(self, slot, fields[slot])


class InvisibleFolderMetadata:
    __slots__ = ("file", "values")

    def __init__(self, file: InvisibleFolderFile, values: dict) -> None:
        self.file = file
        #: metadata key -> {"value": str, "created_at": str | None}
        self.values = values


class DownloadIfNewResult:
    __slots__ = ("downloaded", "revision", "metadata", "bytes", "destination")

    def __init__(self, downloaded: bool, revision: str, metadata: InvisibleFolderMetadata) -> None:
        self.downloaded = downloaded
        self.revision = revision
        self.metadata = metadata
        self.bytes: bytes | None = None
        self.destination: str | None = None


class InvisibleFolder:
    """Access Invisible Folder; obtain a token via init/heartbeat options."""

    def __init__(self, client) -> None:
        self._client = client
        self._token = ""
        self._lock = threading.Lock()

    def set_token(self, token: str) -> None:
        with self._lock:
            self._token = token

    def clear_token(self) -> None:
        with self._lock:
            self._token = ""

    def has_token(self) -> bool:
        with self._lock:
            return self._token != ""

    def _check_prerequisites(self, reference_id: str) -> None:
        if not self._client.config.invisible_folder_base_url.startswith("https://"):
            raise BedrockError(ErrorKind.CONFIGURATION, "Invisible Folder base URL must use HTTPS.")
        if not valid_reference_id(reference_id):
            raise BedrockError(ErrorKind.CONFIGURATION, "Invisible Folder reference ID must be 4 through 128 URL-safe characters.")

    # ── operations ─────────────────────────────────────────────────

    def download(self, reference_id: str) -> bytes:
        self._check_prerequisites(reference_id)
        with self._lock:
            token = self._token
        if token == "":
            raise BedrockError(
                ErrorKind.SESSION_TERMINATED,
                "No Invisible Folder token is available. Request one during initialization or a heartbeat.",
            )

        url = self._client.endpoint(self._client.config.invisible_folder_base_url, DOWNLOAD_PREFIX) + reference_id
        response = self._client.http.post_form(url, {"invisiblefolder_token": token}, {})
        return self._handle_download_response(response, "download")

    def download_to_file(self, reference_id: str, destination: str | Path) -> Path:
        destination = Path(destination)
        if not str(destination):
            raise BedrockError(ErrorKind.CONFIGURATION, "Invisible Folder download destination cannot be empty.")
        payload = self.download(reference_id)
        try:
            destination.write_bytes(payload)
        except OSError as error:
            raise BedrockError(ErrorKind.LOCAL_FAILURE, "Could not write Invisible Folder download destination.") from error
        return destination

    def metadata(self, reference_id: str, keys: list[str] | None = None) -> InvisibleFolderMetadata:
        self._check_prerequisites(reference_id)

        headers: dict[str, str] = {}
        if self._client.config.invisible_folder_api_key:
            headers["X-Api-Key"] = self._client.config.invisible_folder_api_key
        with self._lock:
            if self._token != "":
                headers["X-Invisiblefolder-Token"] = self._token

        url = self._client.endpoint(self._client.config.invisible_folder_base_url, METADATA_PREFIX) + reference_id + METADATA_SUFFIX
        if keys:
            url += "?keys[]=" + "&keys[]=".join(percent_encode(key) for key in keys)

        response = self._client.http.get(url, headers)
        if not response.ok():
            message = _error_message(response)
            if message:
                raise BedrockError(ErrorKind.TRANSPORT, f"Invisible Folder metadata request failed: {message}")
            raise _transport_error("metadata request", response)
        return _parse_metadata(response.body.decode("utf-8"))

    def download_if_new(self, reference_id: str, known_revision: str = "", destination: str | Path | None = None) -> DownloadIfNewResult:
        current = self.metadata(reference_id, [REVISIONS_KEY])
        revision_entry = current.values.get(REVISIONS_KEY)
        if revision_entry is None:
            raise BedrockError(ErrorKind.INVALID_PAYLOAD, "Invisible Folder metadata did not contain __revisions.")

        result = DownloadIfNewResult(False, revision_entry["value"], current)
        if known_revision != "" and known_revision == result.revision:
            return result

        result.downloaded = True
        if destination is not None:
            result.destination = str(self.download_to_file(reference_id, destination))
        else:
            result.bytes = self.download(reference_id)
        return result

    def _handle_download_response(self, response: HTTPResponse, action: str) -> bytes:
        if not response.ok():
            message = _error_message(response)
            if message:
                raise BedrockError(ErrorKind.TRANSPORT, f"Invisible Folder {action} failed: {message}")
            raise _transport_error(action, response)
        return bytes(response.body)


def _error_message(response: HTTPResponse) -> str:
    try:
        payload = json.loads(response.body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return ""
    if isinstance(payload, dict):
        for key in ("message", "error"):
            if isinstance(payload.get(key), str):
                return payload[key]
    return ""


def _transport_error(action: str, response: HTTPResponse) -> BedrockError:
    if response.error:
        return BedrockError(ErrorKind.TRANSPORT, f"Invisible Folder {action} failed: {response.error}")
    return BedrockError(ErrorKind.TRANSPORT, f"Invisible Folder {action} returned HTTP {response.status}.")


def _parse_metadata(body_text: str) -> InvisibleFolderMetadata:
    try:
        payload = json.loads(body_text)
    except ValueError as error:
        raise BedrockError(ErrorKind.INVALID_PAYLOAD, "Invisible Folder metadata JSON is invalid.") from error
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict):
        raise BedrockError(ErrorKind.INVALID_PAYLOAD, "Invisible Folder metadata response has the wrong shape.")
    file = data.get("file")
    metadata = data.get("metadata")
    if not isinstance(file, dict) or not isinstance(metadata, dict):
        raise BedrockError(ErrorKind.INVALID_PAYLOAD, "Invisible Folder metadata response has the wrong shape.")

    for name in FILE_STRING_FIELDS:
        if name not in file or not isinstance(file[name], str):
            raise BedrockError(ErrorKind.INVALID_PAYLOAD, f"Invisible Folder file field '{name}' is missing or has the wrong type.")
    for name in ("size", "downloads"):
        value = file.get(name)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise BedrockError(ErrorKind.INVALID_PAYLOAD, f"Invisible Folder file field '{name}' has the wrong type.")
    permission_type_id = file.get("permission_type_id")
    if not isinstance(permission_type_id, int) or isinstance(permission_type_id, bool):
        raise BedrockError(ErrorKind.INVALID_PAYLOAD, "Invisible Folder file field 'permission_type_id' has the wrong type.")

    values: dict[str, dict] = {}
    for key, entry in metadata.items():
        if not isinstance(entry, dict) or not isinstance(entry.get("value"), str):
            raise BedrockError(ErrorKind.INVALID_PAYLOAD, "Invisible Folder metadata entry has the wrong type.")
        created_at = entry.get("created_at")
        if created_at is not None and not isinstance(created_at, str):
            raise BedrockError(ErrorKind.INVALID_PAYLOAD, "Invisible Folder metadata creation time has the wrong type.")
        values[key] = {"value": entry["value"], "created_at": created_at}

    return InvisibleFolderMetadata(
        InvisibleFolderFile(
            id=file["id"],
            reference_id=file["reference_id"],
            name=file["name"],
            mime_type=file["mime_type"],
            size=file["size"],
            downloads=file["downloads"],
            uploaded_at=file["uploaded_at"],
            permission_type_id=file["permission_type_id"],
        ),
        values,
    )
