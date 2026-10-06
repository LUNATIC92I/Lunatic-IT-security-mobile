"""In-process fake of releases.grapheneos.org for tests (httpx.MockTransport)."""

from __future__ import annotations

import json

import httpx

VERSION = "2026100200"
TIMESTAMP = "1790926302"


class FakeReleaseServer:
    def __init__(
        self, devices=("husky", "shiba", "oriole", "raven", "tegu", "stallion"), overview_missing=("tegu", "stallion")
    ):
        self.devices = set(devices)
        self.overview_missing = set(overview_missing)
        self.down = False
        self.status_override: int | None = None
        self.redirect = False
        self.huge = False
        self.requests: list[str] = []
        self.files: dict[str, bytes] = {}  # path -> content (install zip, .sig, allowed_signers)
        self.cut_after: int | None = None  # simulate a connection drop after N bytes of the image
        self.range_requests: list[str] = []
        self.slow: float = 0.0

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(f"{request.method} {request.url}")
        if self.down:
            raise httpx.ConnectError("connection refused", request=request)
        if self.status_override:
            return httpx.Response(self.status_override)
        if self.redirect:
            return httpx.Response(302, headers={"location": "https://evil.example.com/x"})
        path = request.url.path.lstrip("/")
        if path in self.files:
            return self._serve_file(request, path)
        if path == "overview.json":
            body = {
                d: {"stable": VERSION, "beta": VERSION, "alpha": VERSION}
                for d in sorted(self.devices - self.overview_missing)
            }
            return httpx.Response(200, content=json.dumps(body).encode())
        for channel in ("stable", "beta", "alpha"):
            if path.endswith(f"-{channel}"):
                device = path[: -len(channel) - 1]
                if device not in self.devices or channel == "alpha" and device == "oriole":
                    return httpx.Response(404)
                if self.huge:
                    return httpx.Response(200, content=b"x" * 400_000)
                return httpx.Response(200, content=f"{VERSION} {TIMESTAMP} {device} {channel}\n".encode())
        if path.endswith(".zip") and request.method == "HEAD":
            return httpx.Response(200, headers={"content-length": "1873867524"})
        return httpx.Response(404)

    def _serve_file(self, request: httpx.Request, path: str) -> httpx.Response:
        data = self.files[path]
        if request.method == "HEAD":
            return httpx.Response(200, headers={"content-length": str(len(data))})
        start = 0
        status = 200
        headers = {}
        if "range" in request.headers:
            self.range_requests.append(request.headers["range"])
            start = int(request.headers["range"].split("=")[1].split("-")[0])
            status = 206
            headers["content-range"] = f"bytes {start}-{len(data) - 1}/{len(data)}"
        body = data[start:]
        headers["content-length"] = str(len(body))
        cut = self.cut_after if path.endswith(".zip") else None
        self.cut_after = None if cut is not None else self.cut_after
        return httpx.Response(status, headers=headers, stream=_Stream(body, cut, self.slow))

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)


class _Stream(httpx.SyncByteStream):
    def __init__(self, body: bytes, cut: int | None, slow: float) -> None:
        self.body, self.cut, self.slow = body, cut, slow

    def __iter__(self):
        import time

        sent = 0
        for i in range(0, len(self.body), 65536):
            chunk = self.body[i : i + 65536]
            if self.cut is not None and sent + len(chunk) > self.cut:
                yield chunk[: self.cut - sent]
                raise httpx.ReadError("connection reset by peer")
            if self.slow:
                time.sleep(self.slow)
            sent += len(chunk)
            yield chunk
