"""Synchronous, dependency-free client for a loopback Galleton daemon."""
from __future__ import annotations

import base64
import ipaddress
import json
import re
from dataclasses import dataclass
from http.client import HTTPException
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

__all__ = ["Galleton", "GalletonError", "Response"]


class GalletonError(Exception):
    def __init__(self, code: str, message: str, status: int = 0, retry_at: str | None = None):
        super().__init__(message)
        self.code, self.status, self.retry_at = code, status, retry_at


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


@dataclass(frozen=True)
class Response:
    status: int
    headers: dict[str, list[str]]
    body: bytes
    revision: int

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def text(self, encoding: str = "utf-8") -> str:
        return self.body.decode(encoding)

    def json(self) -> Any:
        return json.loads(self.body)


def _path(session_id: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", session_id):
        raise ValueError("Invalid session ID")
    return "/v1/sessions/" + session_id


class Galleton:
    def __init__(self, token: str, base_url: str = "http://127.0.0.1:8766", timeout: float = 300):
        parsed = urlsplit(base_url)
        try:
            loopback = ipaddress.ip_address(parsed.hostname or "").is_loopback
        except ValueError:
            loopback = False
        if (not loopback or parsed.scheme != "http" or parsed.username or parsed.password
                or parsed.query or parsed.fragment or parsed.path not in ("", "/")):
            raise ValueError("Galleton requires a literal loopback HTTP origin")
        self._base = base_url.rstrip("/")
        self._token = token.strip()
        if not self._token or "\r" in self._token or "\n" in self._token:
            raise ValueError("Invalid local API token")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self._timeout = timeout
        self._opener = build_opener(ProxyHandler({}), _NoRedirect())

    @classmethod
    def from_dir(cls, directory: str | Path, base_url: str = "http://127.0.0.1:8766") -> Galleton:
        return cls((Path(directory) / "api.token").read_text().strip(), base_url)

    def _call(self, method: str, path: str, data: Any = None) -> Any:
        body = None if data is None else json.dumps(data, separators=(",", ":")).encode()
        req = Request(self._base + path, data=body, method=method,
                      headers={"Authorization": "Bearer " + self._token,
                               "Content-Type": "application/json"})
        try:
            response = self._opener.open(req, timeout=self._timeout)
        except HTTPError as exc:
            response = exc
        except (HTTPException, URLError, TimeoutError, OSError):
            raise GalletonError("daemon_unavailable", "Galleton is unavailable or the request timed out.") from None
        status = response.code
        try:
            with response:
                raw = response.read(8 * 1024 * 1024 + 1)
        except (HTTPException, URLError, TimeoutError, OSError):
            raise GalletonError(
                "daemon_unavailable",
                "Galleton response was interrupted; the request may already have completed.",
                status,
            ) from None
        if len(raw) > 8 * 1024 * 1024:
            raise GalletonError("invalid_response", "Oversized daemon response.", status)
        try:
            payload = json.loads(raw)
        except (ValueError, UnicodeError):
            if not 200 <= status < 300:
                raise GalletonError("daemon_error", "Galleton request failed.", status) from None
            raise GalletonError("invalid_response", "Expected a JSON daemon response.", status) from None
        if not 200 <= status < 300:
            error = payload.get("error", {}) if isinstance(payload, dict) else {}
            raise GalletonError(error.get("code", "daemon_error"),
                                  error.get("message", "Galleton request failed."),
                                  status, error.get("retry_at"))
        return payload

    def connect(self, session_id: str, credentials: Mapping[str, Any]) -> dict[str, Any]:
        return self._call("PUT", _path(session_id), dict(credentials))

    def status(self, session_id: str) -> dict[str, Any]:
        return self._call("GET", _path(session_id))

    def list(self) -> list[dict[str, Any]]:
        return self._call("GET", "/v1/sessions")["sessions"]

    def refresh(self, session_id: str) -> dict[str, Any]:
        return self._call("POST", _path(session_id) + "/refresh", {})

    def headers(self, session_id: str, url: str) -> dict[str, str]:
        return self._call("POST", _path(session_id) + "/headers", {"url": url})["headers"]

    def capture(self, session_id: str, url: str, set_cookie: Sequence[str]) -> dict[str, Any]:
        return self._call("POST", _path(session_id) + "/cookies", {"url": url, "set_cookie": list(set_cookie)})

    def forget(self, session_id: str) -> None:
        self._call("DELETE", _path(session_id))

    def request(self, session_id: str, url: str, *, method: str = "GET",
                headers: Mapping[str, str] | None = None, body: str | bytes | None = None) -> Response:
        """Buffer a request through the daemon, capturing replacement cookies.

        No automatic retry is made; upstream non-2xx responses are returned.
        Use headers()/capture() for streaming or an existing HTTP transport.
        """
        raw = body.encode() if isinstance(body, str) else body or b""
        if len(raw) > 1024 * 1024:
            raise ValueError("Request body exceeds 1 MiB")
        data = self._call("POST", _path(session_id) + "/request", {
            "url": url, "method": method, "headers": dict(headers or {}),
            "body_base64": base64.b64encode(raw).decode("ascii")})
        return Response(data["status"], data["headers"],
                        base64.b64decode(data["body_base64"], validate=True), data["revision"])
