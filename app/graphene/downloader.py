"""Download of official GrapheneOS install images, followed by verification.

Pipeline (one job at a time)::

    Download  ->  Verification  ->  Ready
                       |
                       +-> Verification FAILED: files deleted, installation blocked

* The version is always taken from the official metadata on the server side
  (the client only chooses device and channel).
* Files go to ``<downloads>/<codename>-<version>/``; the image is written to
  ``.part`` and resumed with an HTTP ``Range`` request after an interruption.
* HTTPS with certificate validation, official host only, redirects refused,
  size bounded by the size announced by the server (and 4 GiB).
* A successful verification writes ``verified.json`` (SHA-256, SHA-512, size,
  key fingerprint, steps). The installer re-checks the SHA-256 before flashing.
"""

from __future__ import annotations

import json
import os
import shutil
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

from app import __version__
from app.config import HostOS, Settings
from app.core.audit_logger import AuditLogger
from app.core.errors import InvalidInputError, LMSError
from app.core.platform_tools import OperationCancelledError
from app.core.safety import safe_join
from app.graphene import verifier
from app.graphene.compatibility import VERIFIED_BOOT_KEY_HASHES
from app.graphene.releases import VERSION_RE, ReleaseClient, validate_channel, validate_codename
from app.logging_config import get_logger

log = get_logger("graphene.download")

MAX_IMAGE_BYTES = 4 * 1024**3
EXTRACTION_FACTOR = 2.5  # zip + extracted images during installation
CHUNK = 1024 * 1024
VERIFIED_NAME = "verified.json"


class DownloadInProgressError(LMSError):
    code = "download_in_progress"
    http_status = 409
    default_message = "Un téléchargement ou une vérification est déjà en cours."
    default_cause = "Une seule opération GrapheneOS peut s'exécuter à la fois."
    default_action = "Attendez la fin de l'opération en cours ou annulez-la."


class DownloadError(LMSError):
    code = "download_failed"
    http_status = 502
    default_message = "Le téléchargement de GrapheneOS a échoué."
    default_cause = "La connexion au serveur officiel a été interrompue ou la réponse est inattendue."
    default_action = "Vérifiez la connexion Internet puis relancez : le téléchargement reprendra où il s'est arrêté."


class NotEnoughSpaceError(LMSError):
    code = "insufficient_space"
    http_status = 400
    default_message = "Espace disque insuffisant pour télécharger et installer GrapheneOS."
    default_cause = "L'image et sa décompression pendant l'installation nécessitent plusieurs gigaoctets."
    default_action = "Libérez de l'espace ou définissez LMS_DATA_DIR vers un disque plus grand."


class ImageNotFoundError(LMSError):
    code = "image_not_found"
    http_status = 404
    default_message = "Aucune image GrapheneOS téléchargée pour cet appareil et cette version."
    default_cause = "Le fichier n'a pas encore été téléchargé ou a été supprimé."
    default_action = "Téléchargez l'image depuis la page GrapheneOS."


def image_dir(settings: Settings, codename: str, version: str) -> Path:
    validate_codename(codename)
    if not VERSION_RE.fullmatch(version):
        raise InvalidInputError(detail="invalid version")
    return safe_join(settings.downloads_dir, f"{codename}-{version}")


def image_paths(settings: Settings, codename: str, version: str) -> dict[str, Path]:
    base = image_dir(settings, codename, version)
    name = f"{codename}-install-{version}.zip"
    return {
        "dir": base,
        "zip": base / name,
        "part": base / (name + ".part"),
        "sig": base / (name + ".sig"),
        "signers": base / "allowed_signers",
        "verified": base / VERIFIED_NAME,
    }


def read_verified(settings: Settings, codename: str, version: str) -> dict | None:
    paths = image_paths(settings, codename, version)
    if not paths["verified"].is_file() or not paths["zip"].is_file():
        return None
    try:
        data = json.loads(paths["verified"].read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if data.get("codename") != codename or data.get("version") != version or not data.get("ok"):
        return None
    return data


class DownloadManager:
    def __init__(
        self,
        settings: Settings,
        releases: ReleaseClient,
        audit: AuditLogger,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.settings = settings
        self.releases = releases
        self.audit = audit
        self._transport = transport
        self._lock = threading.Lock()
        self._cancel = threading.Event()
        self._thread: threading.Thread | None = None
        self._job: dict = {"state": "idle"}

    # ------------------------------------------------------------- status
    def status(self) -> dict:
        with self._lock:
            job = dict(self._job)
        started = job.pop("started", None)
        finished = job.pop("finished", None)
        if started:
            job["elapsed_seconds"] = round((finished or time.monotonic()) - started, 1)
        return job

    def wait(self, timeout: float | None = None) -> None:
        if self._thread is not None:
            self._thread.join(timeout)

    def cancel(self) -> dict:
        with self._lock:
            running = self._job.get("state") == "running"
        if running:
            self._cancel.set()
        return self.status()

    def _update(self, **values) -> None:
        with self._lock:
            self._job.update(values)

    def _begin(self, kind: str, **info) -> None:
        with self._lock:
            if self._job.get("state") == "running":
                raise DownloadInProgressError()
            self._cancel = threading.Event()
            self._job = {
                "state": "running",
                "kind": kind,
                "phase": "download" if kind == "download" else "verification",
                "bytes_done": 0,
                "bytes_total": None,
                "speed_bps": None,
                "eta_seconds": None,
                "verification": None,
                "error": None,
                "result": None,
                "started": time.monotonic(),
                "finished": None,
                **info,
            }

    # ----------------------------------------------------------- download
    def start_download(self, codename: str, channel: str) -> dict:
        validate_codename(codename)
        validate_channel(channel)
        release = self.releases.release(codename, channel)  # version from the official server
        if release.size_bytes is None or not 0 < release.size_bytes <= MAX_IMAGE_BYTES:
            raise DownloadError(detail=f"unexpected image size announced by the server: {release.size_bytes}")
        paths = image_paths(self.settings, codename, release.version)
        paths["dir"].mkdir(parents=True, exist_ok=True)
        if self.settings.host_os is not HostOS.WINDOWS:
            os.chmod(paths["dir"], 0o700)
        already = paths["part"].stat().st_size if paths["part"].exists() else 0
        needed = int(release.size_bytes * EXTRACTION_FACTOR) - already
        free = shutil.disk_usage(paths["dir"]).free
        if free < needed:
            raise NotEnoughSpaceError(detail=f"needed ~{needed / 1024**3:.1f} GB, available {free / 1024**3:.1f} GB")
        self._begin("download", codename=codename, version=release.version, channel=channel, model=release.model)
        self._update(bytes_total=release.size_bytes, resumed_from=already)
        self.audit.record(
            "graphene_download_started",
            codename=codename,
            version=release.version,
            channel=channel,
            size=release.size_bytes,
            resumed_from=already,
        )
        log.info(
            "GrapheneOS download started: %s %s (%s bytes, resume at %s)",
            codename,
            release.version,
            release.size_bytes,
            already,
        )
        self._thread = threading.Thread(
            target=self._run_download, args=(release, paths), daemon=True, name="graphene-download"
        )
        self._thread.start()
        return self.status()

    def _client(self) -> httpx.Client:
        return httpx.Client(
            transport=self._transport,
            timeout=httpx.Timeout(60.0, connect=15.0),
            follow_redirects=False,
            verify=True,
            headers={"User-Agent": f"LunaticMobileSecurity/{__version__}"},
        )

    def _fetch_small(self, client: httpx.Client, url: str, target: Path, limit: int) -> None:
        response = client.get(url)
        if response.status_code != 200 or len(response.content) > limit:
            raise DownloadError(detail=f"{url.rsplit('/', 1)[-1]}: HTTP {response.status_code}")
        target.write_bytes(response.content)

    def _fetch_image(self, client: httpx.Client, url: str, part: Path, expected: int) -> None:
        offset = part.stat().st_size if part.exists() else 0
        if offset > expected:
            part.unlink()
            offset = 0
        if offset == expected:
            return
        headers = {"Range": f"bytes={offset}-"} if offset else {}
        with client.stream("GET", url, headers=headers) as response:
            if offset and response.status_code == 206:
                content_range = response.headers.get("content-range", "")
                if not content_range.startswith(f"bytes {offset}-") or not content_range.endswith(f"/{expected}"):
                    raise DownloadError(detail=f"unexpected Content-Range {content_range!r}")
                mode = "ab"
            elif response.status_code == 200:
                if response.headers.get("content-length", str(expected)) != str(expected):
                    raise DownloadError(detail="server size differs from the announced size")
                mode, offset = "wb", 0
            else:
                raise DownloadError(detail=f"image: HTTP {response.status_code}")
            done = offset
            window_start, window_bytes = time.monotonic(), 0
            with part.open(mode) as handle:
                for chunk in response.iter_bytes():  # as received: nothing buffered is lost on a drop
                    if self._cancel.is_set():
                        raise OperationCancelledError()
                    done += len(chunk)
                    if done > expected:
                        raise DownloadError(detail="the server sent more data than announced")
                    handle.write(chunk)
                    window_bytes += len(chunk)
                    elapsed = time.monotonic() - window_start
                    if elapsed >= 1:
                        speed = window_bytes / elapsed
                        self._update(
                            bytes_done=done,
                            speed_bps=round(speed),
                            eta_seconds=round((expected - done) / speed) if speed else None,
                        )
                        window_start, window_bytes = time.monotonic(), 0
                    else:
                        self._update(bytes_done=done)
        if done != expected:
            raise DownloadError(detail=f"incomplete download: {done}/{expected} bytes")

    def _run_download(self, release, paths: dict[str, Path]) -> None:
        try:
            with self._client() as client:
                self._fetch_small(client, release.allowed_signers_url, paths["signers"], 4096)
                self._fetch_small(client, release.signature_url, paths["sig"], verifier.MAX_SIG_BYTES)
                self._fetch_image(client, release.install_url, paths["part"], release.size_bytes)
            log.info("GrapheneOS package downloaded: %s", paths["zip"].name)
            self.audit.record("graphene_download_completed", codename=release.codename, version=release.version)
            self._update(phase="verification", bytes_done=release.size_bytes, speed_bps=None, eta_seconds=0)
            self._verify(release.codename, release.version, paths, paths["part"], release.size_bytes)
        except OperationCancelledError:
            self._finish(
                "cancelled",
                error={
                    "code": "cancelled",
                    "message": "Téléchargement annulé.",
                    "cause": "Annulation demandée.",
                    "action": "Relancez-le : il reprendra où il s'est arrêté.",
                    "detail": None,
                },
            )
            self.audit.record("graphene_download_cancelled", codename=release.codename, version=release.version)
        except httpx.HTTPError as exc:
            error = DownloadError(detail=f"{type(exc).__name__}: {str(exc)[:200]}")
            self._finish("failed", error=error.to_dict())
            log.error("GrapheneOS download interrupted: %s", type(exc).__name__)
            self.audit.record(
                "graphene_download_failed", level="ERROR", codename=release.codename, reason=type(exc).__name__
            )
        except LMSError as exc:
            self._finish("failed", error=exc.to_dict())
            self.audit.record("graphene_download_failed", level="ERROR", codename=release.codename, reason=exc.code)
        except OSError as exc:
            error = DownloadError(
                "Erreur d'écriture du fichier téléchargé.",
                cause="Disque plein ou permissions.",
                action="Libérez de l'espace puis relancez.",
                detail=exc.strerror,
            )
            self._finish("failed", error=error.to_dict())

    # ------------------------------------------------------- verification
    def start_verify(self, codename: str, version: str) -> dict:
        paths = image_paths(self.settings, codename, version)
        if not paths["zip"].is_file() or not paths["sig"].is_file() or not paths["signers"].is_file():
            raise ImageNotFoundError()
        self._begin("verify", codename=codename, version=version, channel=None)
        self._update(bytes_total=paths["zip"].stat().st_size)
        expected = None
        previous = read_verified(self.settings, codename, version)
        if previous:
            expected = previous.get("size")
        self._thread = threading.Thread(
            target=self._safe_verify,
            args=(codename, version, paths, paths["zip"], expected),
            daemon=True,
            name="graphene-verify",
        )
        self._thread.start()
        return self.status()

    def _safe_verify(self, codename, version, paths, source, expected) -> None:
        try:
            self._verify(codename, version, paths, source, expected)
        except OperationCancelledError:
            self._finish(
                "cancelled",
                error={
                    "code": "cancelled",
                    "message": "Vérification annulée.",
                    "cause": None,
                    "action": "Relancez la vérification.",
                    "detail": None,
                },
            )

    def _verify(self, codename: str, version: str, paths: dict[str, Path], source: Path, expected: int | None) -> None:
        self._update(phase="verification", verify_done=0)
        report = verifier.verify_image(
            source,
            paths["sig"],
            paths["signers"].read_text(encoding="utf-8", errors="replace"),
            codename=codename,
            version=version,
            expected_size=expected,
            expected_avb_key_sha256=VERIFIED_BOOT_KEY_HASHES.get(codename),
            cancel=self._cancel,
            progress=lambda n: self._update(verify_done=n),
        )
        summary = {
            "ok": report.ok,
            "codename": codename,
            "version": version,
            "size": report.size,
            "sha256": report.sha256,
            "sha512": report.sha512,
            "key_fingerprint": report.key_fingerprint,
            "steps": report.steps,
            "verified_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "app_version": __version__,
        }
        if report.ok:
            if source != paths["zip"]:
                source.replace(paths["zip"])
            paths["verified"].write_text(json.dumps(summary, indent=2), encoding="utf-8")
            if self.settings.host_os is not HostOS.WINDOWS:
                os.chmod(paths["verified"], 0o600)
            log.info("GrapheneOS image verified: SHA256 %s, signature OK", report.sha256)
            self.audit.record(
                "graphene_image_verified",
                codename=codename,
                version=version,
                sha256=report.sha256,
                key=report.key_fingerprint,
            )
            self._finish("completed", result="ready", verification=summary)
        else:
            # Corrupted or unexpected file: never keep it around.
            for key in ("zip", "part", "verified"):
                paths[key].unlink(missing_ok=True)
            failed = [s for s in report.steps if not s["ok"]]
            log.error("GrapheneOS verification FAILED (%s): installation blocked", failed[0]["step"] if failed else "?")
            self.audit.record(
                "graphene_verification_failed",
                level="ERROR",
                codename=codename,
                version=version,
                failed_steps=[s["step"] for s in failed],
            )
            error = {
                "code": "verification_failed",
                "message": "Verification FAILED — Installation blocked.",
                "cause": failed[0]["detail"] if failed else "Vérification incomplète.",
                "action": "Le fichier a été supprimé. Relancez le téléchargement ; si l'échec persiste, "
                "n'installez pas et signalez-le (connexion compromise possible).",
                "detail": None,
            }
            self._finish("failed", result="verification_failed", verification=summary, error=error)

    def _finish(self, state: str, **values) -> None:
        with self._lock:
            self._job.update(state=state, finished=time.monotonic(), **values)

    # ------------------------------------------------------------- images
    def list_images(self) -> list[dict]:
        root = self.settings.downloads_dir
        images = []
        if not root.is_dir():
            return images
        for entry in sorted(root.iterdir(), reverse=True):
            if not entry.is_dir() or "-" not in entry.name:
                continue
            codename, _, version = entry.name.rpartition("-")
            try:
                paths = image_paths(self.settings, codename, version)
            except LMSError:
                continue
            verified = read_verified(self.settings, codename, version)
            part = paths["part"].stat().st_size if paths["part"].exists() else None
            images.append(
                {
                    "codename": codename,
                    "version": version,
                    "status": "ready"
                    if verified
                    else "partial"
                    if part
                    else "unverified"
                    if paths["zip"].exists()
                    else "empty",
                    "size": paths["zip"].stat().st_size if paths["zip"].exists() else part,
                    "sha256": verified.get("sha256") if verified else None,
                    "verified_at": verified.get("verified_at") if verified else None,
                }
            )
        return images

    def delete_image(self, codename: str, version: str) -> None:
        with self._lock:
            if (
                self._job.get("state") == "running"
                and self._job.get("codename") == codename
                and self._job.get("version") == version
            ):
                raise DownloadInProgressError()
        directory = image_paths(self.settings, codename, version)["dir"]
        if not directory.is_dir():
            raise ImageNotFoundError()
        shutil.rmtree(directory)
        self.audit.record("graphene_image_deleted", codename=codename, version=version)
        log.info("GrapheneOS image deleted: %s %s", codename, version)
