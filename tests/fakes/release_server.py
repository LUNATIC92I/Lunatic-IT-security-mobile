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

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(f"{request.method} {request.url}")
        if self.down:
            raise httpx.ConnectError("connection refused", request=request)
        if self.status_override:
            return httpx.Response(self.status_override)
        if self.redirect:
            return httpx.Response(302, headers={"location": "https://evil.example.com/x"})
        path = request.url.path.lstrip("/")
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

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)
