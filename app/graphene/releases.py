"""Official GrapheneOS release metadata.

Sources (the only ones used, see ``Settings.grapheneos_releases_url``):

* ``https://releases.grapheneos.org/overview.json`` — latest version per device
  and channel (the file read by the official releases page);
* ``https://releases.grapheneos.org/<codename>-<channel>`` — one line:
  ``VERSION UNIX_TIMESTAMP CODENAME CHANNEL``;
* install image ``<codename>-install-<version>.zip`` with its signature
  ``.zip.sig`` and the signing key file ``allowed_signers``.

Every response is size-limited, strictly parsed and cross-checked (the
metadata must name the requested device and channel). HTTPS certificate
validation is always on; redirects are refused.
"""

from __future__ import annotations

import json
import re
import threading
import time
from datetime import datetime, timezone

import httpx

from app import __version__
from app.config import Settings
from app.core.errors import InvalidInputError, LMSError
from app.graphene.compatibility import SUPPORTED_DEVICES
from app.logging_config import get_logger
from app.models.graphene_release import GrapheneRelease

log = get_logger("graphene.releases")

CHANNELS = ("stable", "beta", "alpha")
VERSION_RE = re.compile(r"\d{10}")
CODENAME_RE = re.compile(r"[a-z][a-z0-9]{1,20}")
MAX_METADATA_BYTES = 256 * 1024
CACHE_SECONDS = 300


class ReleaseServerError(LMSError):
    code = "release_server_unreachable"
    http_status = 502
    default_message = "Impossible d'obtenir les informations de version GrapheneOS."
    default_cause = "Le serveur officiel releases.grapheneos.org est injoignable ou a renvoyé une réponse inattendue."
    default_action = "Vérifiez la connexion Internet (proxy, pare-feu) puis réessayez."


class NoReleaseError(LMSError):
    code = "no_release"
    http_status = 404
    default_message = "Aucune version officielle n'est publiée pour cet appareil sur ce canal."
    default_cause = "L'appareil n'est pas (ou plus) pris en charge, ou ce canal ne propose pas de version."
    default_action = "Consultez https://grapheneos.org/releases ou choisissez le canal Stable."


def validate_codename(codename: str) -> str:
    if not isinstance(codename, str) or not CODENAME_RE.fullmatch(codename):
        raise InvalidInputError(detail="invalid device codename")
    return codename


def validate_channel(channel: str) -> str:
    if channel not in CHANNELS:
        raise InvalidInputError(detail=f"channel must be one of {CHANNELS}")
    return channel


def build_date(version: str) -> str:
    return f"{version[0:4]}-{version[4:6]}-{version[6:8]}"


def parse_channel_metadata(text: str, codename: str, channel: str) -> tuple[str, int]:
    """Parse ``VERSION TIMESTAMP CODENAME CHANNEL`` and cross-check it."""
    parts = text.strip().split()
    if len(parts) != 4:
        raise ReleaseServerError(detail=f"unexpected metadata format: {text.strip()[:80]!r}")
    version, timestamp, device, chan = parts
    if not VERSION_RE.fullmatch(version) or not timestamp.isdigit():
        raise ReleaseServerError(detail="invalid version or timestamp in metadata")
    if device != codename or chan != channel:
        raise ReleaseServerError(detail=f"metadata is for {device}/{chan}, expected {codename}/{channel}")
    return version, int(timestamp)


def parse_overview(data: object) -> dict[str, dict[str, str]]:
    if not isinstance(data, dict):
        raise ReleaseServerError(detail="overview.json is not an object")
    overview: dict[str, dict[str, str]] = {}
    for codename, channels in data.items():
        if not isinstance(codename, str) or not CODENAME_RE.fullmatch(codename) or not isinstance(channels, dict):
            continue
        overview[codename] = {
            ch: v for ch, v in channels.items() if ch in CHANNELS and isinstance(v, str) and VERSION_RE.fullmatch(v)
        }
    return overview


class ReleaseClient:
    def __init__(self, settings: Settings, transport: httpx.BaseTransport | None = None) -> None:
        self.base = settings.grapheneos_releases_url.rstrip("/")
        self._transport = transport
        self._lock = threading.Lock()
        self._overview: tuple[float, dict] | None = None

    def _client(self) -> httpx.Client:
        return httpx.Client(
            transport=self._transport,
            timeout=httpx.Timeout(20.0, connect=10.0),
            follow_redirects=False,
            verify=True,
            headers={"User-Agent": f"LunaticMobileSecurity/{__version__}"},
        )

    def url(self, name: str) -> str:
        return f"{self.base}/{name}"

    def _get_small(self, name: str) -> bytes:
        url = self.url(name)
        try:
            with self._client() as client, client.stream("GET", url) as response:
                if response.status_code == 404:
                    raise NoReleaseError(detail=f"{name}: 404")
                if response.status_code != 200:
                    raise ReleaseServerError(detail=f"{name}: HTTP {response.status_code}")
                body = b""
                for chunk in response.iter_bytes():
                    body += chunk
                    if len(body) > MAX_METADATA_BYTES:
                        raise ReleaseServerError(detail=f"{name}: response too large")
                return body
        except httpx.HTTPError as exc:
            log.error("Release server request failed: %s (%s)", name, type(exc).__name__)
            raise ReleaseServerError(detail=f"{type(exc).__name__}: {str(exc)[:200]}") from exc

    def overview(self, force: bool = False) -> dict[str, dict[str, str]]:
        with self._lock:
            cached = self._overview
        if cached and not force and time.monotonic() - cached[0] < CACHE_SECONDS:
            return cached[1]
        try:
            data = parse_overview(json.loads(self._get_small("overview.json")))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ReleaseServerError(detail="overview.json is not valid JSON") from exc
        with self._lock:
            self._overview = (time.monotonic(), data)
        log.info("GrapheneOS release overview fetched (%s devices)", len(data))
        return data

    def head_size(self, url: str) -> int | None:
        try:
            with self._client() as client:
                response = client.head(url)
            if response.status_code == 200 and response.headers.get("content-length", "").isdigit():
                return int(response.headers["content-length"])
        except httpx.HTTPError:
            return None
        return None

    def release(self, codename: str, channel: str = "stable", with_size: bool = True) -> GrapheneRelease:
        validate_codename(codename)
        validate_channel(channel)
        if codename not in SUPPORTED_DEVICES:
            raise NoReleaseError(
                "Cet appareil ne fait pas partie des appareils pris en charge par GrapheneOS.",
                action="Consultez la liste des appareils pris en charge dans la page GrapheneOS.",
            )
        text = self._get_small(f"{codename}-{channel}").decode("ascii", errors="replace")
        version, timestamp = parse_channel_metadata(text, codename, channel)
        install = self.url(f"{codename}-install-{version}.zip")
        release = GrapheneRelease(
            codename=codename,
            model=SUPPORTED_DEVICES[codename].model,
            channel=channel,
            version=version,
            build_date=build_date(version),
            published_at=datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(timespec="seconds"),
            install_url=install,
            signature_url=install + ".sig",
            allowed_signers_url=self.url("allowed_signers"),
            size_bytes=self.head_size(install) if with_size else None,
            source=self.url(f"{codename}-{channel}"),
        )
        log.info("GrapheneOS %s release for %s: %s", channel, codename, version)
        return release
