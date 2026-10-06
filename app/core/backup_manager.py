"""Backup of the data Android lets ADB read without root.

What is backed up
-----------------
* shared-storage folders of user 0 (DCIM, Pictures, Movies, Music, Documents,
  Download, Recordings, …) with ``adb pull``;
* optionally the APK files of third-party apps (to reinstall them; their
  *data* stays inaccessible).

What cannot be backed up (stated in the UI, never simulated)
------------------------------------------------------------
Application private data, SMS, call log and contacts are protected by Android:
ADB without root cannot read them, and ``adb backup`` is deprecated and ignored
by modern apps. ``Android/`` (app-specific storage) is excluded on purpose.

Integrity
---------
1. Before transfer, the SHA-256 of every file is computed **on the phone**
   (``find … -exec sha256sum``).
2. Files are pulled into ``<name>.partial``.
3. Every file is hashed again **on the computer** and compared.
4. ``SHA256SUMS`` (``sha256sum -c`` compatible) and ``backup.json`` are written,
   then the folder is renamed. The backup is "verified" only if every file
   matches; anything else is reported precisely.

A cancelled or failed backup removes its ``.partial`` folder.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from app import __version__
from app.config import HostOS, Settings
from app.core.audit_logger import AuditLogger
from app.core.errors import InvalidInputError, LMSError, PathSecurityError
from app.core.platform_tools import SHARED_FOLDERS, SHARED_STORAGE_ROOT, OperationCancelledError
from app.core.safety import safe_join
from app.core.security_scanner import SecurityScanner
from app.logging_config import get_logger, redact
from app.security.applications import parse_package_list

log = get_logger("backup")

SPACE_MARGIN = 1.05
SPACE_RESERVE = 200 * 1024 * 1024
HASH_CHUNK = 1024 * 1024
MANIFEST_NAME = "SHA256SUMS"
METADATA_NAME = "backup.json"

NOT_BACKED_UP = [
    "Données privées des applications (conversations, réglages, comptes) : protégées par Android, inaccessibles "
    "sans root. Utilisez la sauvegarde intégrée de chaque application ou celle du système.",
    "SMS, journal d'appels et contacts : non lisibles via ADB sans root. Exportez vos contacts au format .vcf "
    "dans « Download » depuis l'application Contacts pour qu'ils soient inclus.",
    "« adb backup » n'est pas utilisé : il est obsolète et ignoré par les applications récentes.",
    "Dossier Android/ (stockage propre aux applications) : exclu volontairement.",
]


class BackupInProgressError(LMSError):
    code = "backup_in_progress"
    http_status = 409
    default_message = "Une sauvegarde est déjà en cours."
    default_cause = "Une seule sauvegarde peut être exécutée à la fois."
    default_action = "Attendez la fin de la sauvegarde en cours ou annulez-la."


class BackupDestinationError(LMSError):
    code = "backup_destination"
    http_status = 400
    default_message = "Dossier de destination inutilisable."
    default_cause = "Le dossier n'existe pas, n'est pas un dossier ou n'est pas accessible en écriture."
    default_action = "Choisissez un dossier existant sur lequel vous avez les droits d'écriture."


class InsufficientSpaceError(LMSError):
    code = "insufficient_space"
    http_status = 400
    default_message = "Espace disque insuffisant pour cette sauvegarde."
    default_cause = "Le dossier de destination ne dispose pas d'assez d'espace libre."
    default_action = "Libérez de l'espace, choisissez un autre disque ou réduisez la sélection de dossiers."


# ------------------------------------------------------------------ parsing
def parse_du(output: str) -> int | None:
    """``du -sk <dir>`` → bytes (``123456\\t/storage/emulated/0/DCIM``)."""
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].isdigit():
            return int(parts[0]) * 1024
    return None


def parse_sha256_list(output: str) -> dict[str, str]:
    """``sha256sum`` lines (``<64 hex>  <path>``) → {path: hash}."""
    hashes: dict[str, str] = {}
    for line in output.splitlines():
        if len(line) > 66 and line[64:66] == "  ":
            digest, path = line[:64].lower(), line[66:]
            if all(c in "0123456789abcdef" for c in digest) and path.startswith("/"):
                hashes[path] = digest
    return hashes


def parse_pm_path(output: str) -> list[str]:
    return [
        line.strip()[len("package:") :]
        for line in output.splitlines()
        if line.strip().startswith("package:/data/app/") and line.strip().endswith(".apk")
    ]


def sha256_file(path: Path, cancel: threading.Event | None = None) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(HASH_CHUNK):
            if cancel is not None and cancel.is_set():
                raise OperationCancelledError()
            digest.update(chunk)
    return digest.hexdigest()


def directory_size(path: Path) -> int:
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += (Path(root) / name).stat().st_size
            except OSError:
                continue
    return total


def human(size: int | None) -> str:
    if size is None:
        return "?"
    value = float(size)
    for unit in ("o", "Ko", "Mo", "Go", "To"):
        if value < 1024 or unit == "To":
            return f"{value:.1f} {unit}" if unit != "o" else f"{int(value)} o"
        value /= 1024
    return f"{value:.1f} To"


# ------------------------------------------------------------------ manager
class BackupManager:
    def __init__(self, settings: Settings, scanner: SecurityScanner, audit: AuditLogger) -> None:
        self.settings = settings
        self.scanner = scanner
        self.runner = scanner.devices.runner
        self.audit = audit
        self._lock = threading.Lock()
        self._job: dict = {"state": "idle"}
        self._cancel = threading.Event()
        self._thread: threading.Thread | None = None

    # ---------------------------------------------------------- destination
    def resolve_destination(self, raw: str | None, *, check_writable: bool = True) -> Path:
        if raw is None or not raw.strip():
            self.settings.ensure_directories()
            return self.settings.backups_dir
        if "\x00" in raw or len(raw) > 4096:
            raise BackupDestinationError(detail="invalid characters")
        path = Path(raw.strip()).expanduser()
        if not path.is_absolute():
            raise BackupDestinationError(
                "Le chemin doit être absolu.", action="Indiquez un chemin complet, par exemple /home/moi/Sauvegardes."
            )
        path = path.resolve()
        if not path.is_dir():
            raise BackupDestinationError(detail=f"{path} is not a directory")
        if check_writable:
            try:
                with tempfile.NamedTemporaryFile(dir=path, prefix=".lms-write-test-"):
                    pass
            except OSError as exc:
                raise BackupDestinationError(detail=exc.strerror) from exc
        return path

    def browse(self, raw: str | None) -> dict:
        """List sub-directories (never files) to pick a destination."""
        path = Path(raw).expanduser() if raw else Path.home()
        if not path.is_absolute():
            raise BackupDestinationError("Le chemin doit être absolu.")
        path = path.resolve()
        if not path.is_dir():
            raise BackupDestinationError(detail=f"{path} is not a directory")
        try:
            names = sorted(
                (e.name for e in os.scandir(path) if e.is_dir(follow_symlinks=False) and not e.name.startswith(".")),
                key=str.lower,
            )
        except OSError as exc:
            raise BackupDestinationError("Impossible de lire ce dossier.", detail=exc.strerror) from exc
        try:
            free = shutil.disk_usage(path).free
        except OSError:
            free = None
        return {
            "path": str(path),
            "parent": str(path.parent) if path.parent != path else None,
            "directories": names[:500],
            "writable": os.access(path, os.W_OK),
            "free_bytes": free,
            "default": str(self.settings.backups_dir),
        }

    # ------------------------------------------------------------- estimate
    def estimate(self, device_id: str | None) -> dict:
        connection, serial = self.scanner.resolve_adb(device_id)
        folders = []
        for name in SHARED_FOLDERS:
            size = None
            try:
                result = self.runner.run(
                    "adb.du_shared", serial=serial, params={"folder": f"{SHARED_STORAGE_ROOT}/{name}"}
                )
                size = parse_du(result.stdout) if result.stdout.strip() else None
                exists = size is not None
            except LMSError:
                exists = False
            folders.append({"name": name, "bytes": size, "exists": exists, "label": human(size)})
        try:
            third_party = sorted(parse_package_list(self.runner.run("adb.pm_list_third_party", serial=serial).stdout))
        except LMSError:
            third_party = []
        return {
            "device_id": connection.device_id,
            "serial_masked": connection.serial_masked,
            "folders": folders,
            "third_party_apps": len(third_party),
            "not_backed_up": NOT_BACKED_UP,
        }

    # ----------------------------------------------------------------- jobs
    def status(self) -> dict:
        with self._lock:
            job = dict(self._job)
        if job.get("started"):
            job["elapsed_seconds"] = round((job.get("finished") or time.monotonic()) - job["started"], 1)
        job.pop("started", None)
        job.pop("finished", None)
        return job

    def cancel(self) -> dict:
        with self._lock:
            running = self._job.get("state") == "running"
        if running:
            self._cancel.set()
            log.warning("Backup cancellation requested")
        return self.status()

    def wait(self, timeout: float | None = None) -> None:
        if self._thread is not None:
            self._thread.join(timeout)

    def start(self, device_id: str | None, folders: list[str], include_apks: bool, destination: str | None) -> dict:
        with self._lock:
            if self._job.get("state") == "running":
                raise BackupInProgressError()
        unknown = [f for f in folders if f not in SHARED_FOLDERS]
        if unknown or len(set(folders)) != len(folders):
            raise InvalidInputError(detail=f"unknown or duplicated folders: {unknown}")
        if not folders and not include_apks:
            raise InvalidInputError(
                "Rien à sauvegarder.", action="Sélectionnez au moins un dossier ou les APK des applications."
            )
        connection, serial = self.scanner.resolve_adb(device_id)
        dest_root = self.resolve_destination(destination)

        estimated = 0
        for name in folders:
            result = self.runner.run("adb.du_shared", serial=serial, params={"folder": f"{SHARED_STORAGE_ROOT}/{name}"})
            estimated += parse_du(result.stdout) or 0
        free = shutil.disk_usage(dest_root).free
        needed = int(estimated * SPACE_MARGIN) + SPACE_RESERVE
        if free < needed:
            raise InsufficientSpaceError(
                detail=f"besoin estimé {human(needed)}, disponible {human(free)} dans {dest_root}",
            )

        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        model = "".join(c for c in (connection.codename_hint or connection.model_hint or "android") if c.isalnum())
        final = safe_join(dest_root, f"LMS-backup-{model or 'android'}-{stamp}")
        partial = safe_join(dest_root, final.name + ".partial")
        if final.exists() or partial.exists():
            raise BackupDestinationError(detail="backup folder already exists")

        with self._lock:
            if self._job.get("state") == "running":
                raise BackupInProgressError()
            self._cancel = threading.Event()
            self._job = {
                "state": "running",
                "step": "Préparation",
                "progress": 0,
                "bytes_total": estimated,
                "bytes_done": 0,
                "files_total": 0,
                "files_verified": 0,
                "mismatches": [],
                "missing": [],
                "changed_during_backup": [],
                "errors": [],
                "backup_path": None,
                "error": None,
                "result": None,
                "started": time.monotonic(),
                "finished": None,
            }
            self._thread = threading.Thread(
                target=self._run,
                args=(connection, serial, folders, include_apks, partial, final, estimated),
                name="backup",
                daemon=True,
            )
        self.audit.record(
            "backup_started",
            device_id=connection.device_id,
            folders=folders,
            include_apks=include_apks,
            destination=str(dest_root),
            estimated_bytes=estimated,
        )
        log.info("Backup started: %s folder(s), APKs=%s, %s estimated", len(folders), include_apks, human(estimated))
        self._thread.start()
        return self.status()

    def _update(self, **values) -> None:
        with self._lock:
            self._job.update(values)

    def _monitor(self, partial: Path, stop: threading.Event) -> None:
        while not stop.wait(1.0):
            done = directory_size(partial) if partial.exists() else 0
            with self._lock:
                total = self._job.get("bytes_total") or 0
                self._job["bytes_done"] = done
                if total:
                    self._job["progress"] = min(95, round(done * 95 / total))

    def _run(self, connection, serial, folders, include_apks, partial: Path, final: Path, estimated: int) -> None:
        stop = threading.Event()
        monitor = threading.Thread(target=self._monitor, args=(partial, stop), daemon=True)
        manifest: dict[str, str] = {}  # relative path -> device hash
        notes: list[str] = []
        try:
            partial.mkdir(mode=0o700)
            monitor.start()
            for name in folders:
                self._backup_folder(serial, name, partial, manifest, notes)
            if include_apks:
                self._backup_apks(serial, partial, manifest, notes)
            stop.set()
            self._finish(connection, partial, final, manifest, notes, folders, include_apks)
        except OperationCancelledError:
            stop.set()
            self._abort(
                partial,
                "cancelled",
                {
                    "code": "cancelled",
                    "message": "Sauvegarde annulée.",
                    "cause": "Annulation demandée.",
                    "action": "Relancez-la si nécessaire.",
                    "detail": None,
                },
                connection,
            )
        except LMSError as exc:
            stop.set()
            self._abort(partial, "failed", exc.to_dict(), connection)
        except OSError as exc:
            stop.set()
            error = BackupDestinationError(
                "Erreur d'écriture pendant la sauvegarde.",
                cause="Disque plein, support retiré ou permissions insuffisantes.",
                action="Vérifiez le disque de destination puis relancez la sauvegarde.",
                detail=exc.strerror,
            )
            self._abort(partial, "failed", error.to_dict(), connection)
        except Exception:  # noqa: BLE001 - must never kill the worker silently
            stop.set()
            log.exception("Unexpected error during backup")
            self._abort(partial, "failed", LMSError(detail="unexpected error during backup").to_dict(), connection)

    def _backup_folder(self, serial: str, name: str, partial: Path, manifest: dict, notes: list) -> None:
        remote = f"{SHARED_STORAGE_ROOT}/{name}"
        self._update(step=f"Empreintes SHA-256 sur le téléphone : {name}")
        result = self.runner.run("adb.hash_shared", serial=serial, params={"folder": remote}, cancel=self._cancel)
        hashes = parse_sha256_list(result.stdout)
        phone_error = redact(result.stderr.strip())[:200]
        if not hashes:
            if result.returncode != 0 and phone_error and "no such file" not in phone_error.lower():
                with self._lock:
                    self._job["errors"].append(
                        f"{name} : empreintes impossibles à calculer sur le téléphone ({phone_error})."
                    )
            else:
                notes.append(f"{name} : dossier vide ou absent, rien à copier.")
            return
        if result.returncode != 0 and phone_error:
            # Those files are neither copied nor certified: the backup cannot be called verified.
            with self._lock:
                self._job["errors"].append(
                    f"{name} : certains fichiers n'ont pas pu être lus sur le téléphone ({phone_error})."
                )
        relative = {}
        for path, digest in hashes.items():
            rel = "shared/" + path[len(SHARED_STORAGE_ROOT) + 1 :]
            relative[rel] = digest
        with self._lock:
            self._job["files_total"] += len(relative)

        self._update(step=f"Transfert : {name} ({len(relative)} fichiers)")
        shared = partial / "shared"
        shared.mkdir(exist_ok=True)
        self.runner.run(
            "adb.pull_shared",
            serial=serial,
            params={"folder": remote, "destination": str(shared)},
            cancel=self._cancel,
            check=True,
        )
        self._update(step=f"Vérification SHA-256 : {name}")
        self._verify_files(partial, relative, manifest)
        # Files present locally but not hashed beforehand were created during the backup.
        known = set(relative)
        for local in (partial / "shared" / name).rglob("*"):
            if local.is_file():
                rel = local.relative_to(partial).as_posix()
                if rel not in known:
                    with self._lock:
                        self._job["changed_during_backup"].append(rel)

    def _verify_files(self, partial: Path, expected: dict[str, str], manifest: dict) -> None:
        for rel, digest in expected.items():
            if self._cancel.is_set():
                raise OperationCancelledError()
            try:
                local = safe_join(partial, *rel.split("/"))
            except PathSecurityError:
                with self._lock:
                    self._job["errors"].append(f"Chemin refusé (hors du dossier de sauvegarde) : {rel}")
                continue
            if not local.is_file():
                with self._lock:
                    self._job["missing"].append(rel)
                continue
            actual = sha256_file(local, self._cancel)
            with self._lock:
                if actual == digest:
                    self._job["files_verified"] += 1
                    manifest[rel] = digest
                else:
                    self._job["mismatches"].append(rel)

    def _backup_apks(self, serial: str, partial: Path, manifest: dict, notes: list) -> None:
        self._update(step="Liste des applications tierces")
        packages = sorted(parse_package_list(self.runner.run("adb.pm_list_third_party", serial=serial).stdout))
        apk_root = partial / "apks"
        apk_root.mkdir(exist_ok=True)
        for index, package in enumerate(packages, start=1):
            if self._cancel.is_set():
                raise OperationCancelledError()
            self._update(step=f"APK {index}/{len(packages)} : {package}")
            try:
                located = self.runner.run("adb.pm_path", serial=serial, params={"package": package})
            except LMSError as exc:
                notes.append(f"{package} : emplacement de l'APK non lisible ({exc.message}).")
                continue
            paths = parse_pm_path(located.stdout) if located.ok else []
            if not paths:
                notes.append(f"{package} : aucun APK accessible (application installée pour un autre profil ?).")
                continue
            target = safe_join(apk_root, package)
            target.mkdir(exist_ok=True)
            expected: dict[str, str] = {}
            for apk in paths:
                try:
                    digest = parse_sha256_list(
                        self.runner.run(
                            "adb.sha256_apk", serial=serial, params={"apk": apk}, cancel=self._cancel
                        ).stdout
                    ).get(apk)
                    self.runner.run(
                        "adb.pull_apk",
                        serial=serial,
                        params={"apk": apk, "destination": str(target)},
                        cancel=self._cancel,
                        check=True,
                    )
                except OperationCancelledError:
                    raise
                except LMSError as exc:
                    notes.append(f"{package} : APK non copié ({exc.message}).")
                    continue
                if digest is None:
                    notes.append(f"{package} : empreinte de {apk.rsplit('/', 1)[-1]} non calculable sur le téléphone.")
                    continue
                expected[f"apks/{package}/{apk.rsplit('/', 1)[-1]}"] = digest
            with self._lock:
                self._job["files_total"] += len(expected)
            self._verify_files(partial, expected, manifest)

    def _finish(self, connection, partial: Path, final: Path, manifest: dict, notes: list, folders, include_apks):
        self._update(step="Écriture du manifeste")
        with self._lock:
            job = dict(self._job)
        lines = [f"{digest}  {rel}" for rel, digest in sorted(manifest.items())]
        (partial / MANIFEST_NAME).write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        # Files copied but absent from the phone-side hash list (created during the backup, or
        # with a name sha256sum had to escape) are not certified: the backup is then incomplete.
        verified = (
            not job["mismatches"] and not job["missing"] and not job["errors"] and not job["changed_during_backup"]
        )
        size = directory_size(partial)
        metadata = {
            "format": "lunatic-mobile-security-backup/1",
            "app_version": __version__,
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "device": {
                "serial_masked": connection.serial_masked,
                "model": connection.model_hint,
                "codename": connection.codename_hint,
            },
            "folders": folders,
            "include_apks": include_apks,
            "files": len(manifest),
            "bytes": size,
            "status": "verified" if verified else "incomplete",
            "mismatches": job["mismatches"],
            "missing": job["missing"],
            "changed_during_backup": job["changed_during_backup"],
            "errors": job["errors"],
            "notes": notes,
            "not_backed_up": NOT_BACKED_UP,
            "manifest": MANIFEST_NAME,
        }
        (partial / METADATA_NAME).write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")
        partial.rename(final)
        if self.settings.host_os is not HostOS.WINDOWS:
            os.chmod(final, 0o700)
        with self._lock:
            self._job.update(
                state="completed",
                step="Terminé",
                progress=100,
                bytes_done=size,
                backup_path=str(final),
                result=metadata["status"],
                notes=notes,
                finished=time.monotonic(),
            )
        if verified:
            log.info("Backup completed and SHA256 verified: %s files, %s", len(manifest), human(size))
        else:
            log.warning(
                "Backup completed with problems: %s mismatch(es), %s missing",
                len(job["mismatches"]),
                len(job["missing"]),
            )
        self.audit.record(
            "backup_completed",
            level="INFO" if verified else "WARN",
            device_id=connection.device_id,
            status=metadata["status"],
            files=len(manifest),
            bytes=size,
            mismatches=len(job["mismatches"]),
            missing=len(job["missing"]),
            path=str(final),
        )

    def _abort(self, partial: Path, state: str, error: dict, connection) -> None:
        removed = False
        if partial.name.endswith(".partial") and partial.exists():
            shutil.rmtree(partial, ignore_errors=True)
            removed = not partial.exists()
        with self._lock:
            self._job.update(
                state=state,
                error=error,
                step="Annulée" if state == "cancelled" else "Échec",
                finished=time.monotonic(),
                partial_removed=removed,
            )
        log.error("Backup %s: %s", state.upper(), error.get("message"))
        self.audit.record(
            f"backup_{state}",
            level="WARN" if state == "cancelled" else "ERROR",
            device_id=connection.device_id,
            reason=error.get("code"),
            partial_removed=removed,
        )

    # -------------------------------------------------- existing backups
    def list_backups(self, destination: str | None) -> dict:
        root = self.resolve_destination(destination, check_writable=False)  # read-only listing (GET)
        backups = []
        for entry in sorted(root.iterdir(), reverse=True):
            meta_path = entry / METADATA_NAME
            if entry.is_dir() and meta_path.is_file():
                try:
                    meta = json.loads(meta_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                backups.append(
                    {
                        "path": str(entry),
                        "name": entry.name,
                        "created_at": meta.get("created_at"),
                        "device": meta.get("device", {}),
                        "files": meta.get("files"),
                        "bytes": meta.get("bytes"),
                        "status": meta.get("status"),
                        "folders": meta.get("folders", []),
                        "include_apks": meta.get("include_apks", False),
                    }
                )
        return {"destination": str(root), "backups": backups[:200]}

    def verify_backup(self, raw_path: str) -> dict:
        """Re-hash every file listed in SHA256SUMS (detects later corruption)."""
        if not raw_path or "\x00" in raw_path or not Path(raw_path).is_absolute():
            raise BackupDestinationError("Chemin de sauvegarde invalide.")
        root = Path(raw_path).resolve()
        manifest_path = root / MANIFEST_NAME
        if not (root / METADATA_NAME).is_file() or not manifest_path.is_file():
            raise BackupDestinationError(
                "Ce dossier n'est pas une sauvegarde LUNATIC MOBILE SECURITY.",
                cause=f"{METADATA_NAME} ou {MANIFEST_NAME} est absent.",
                action="Sélectionnez un dossier de sauvegarde complet.",
            )
        ok, mismatches, missing, rejected = 0, [], [], []
        for line in manifest_path.read_text(encoding="utf-8").splitlines():
            if len(line) < 67 or line[64:66] != "  ":
                continue
            digest, rel = line[:64], line[66:]
            try:
                local = safe_join(root, *rel.split("/"))
            except PathSecurityError:
                rejected.append(rel)
                continue
            if not local.is_file():
                missing.append(rel)
            elif sha256_file(local) == digest:
                ok += 1
            else:
                mismatches.append(rel)
        valid = not mismatches and not missing and not rejected
        log.info(
            "Backup verification %s: %s ok, %s mismatch, %s missing",
            "OK" if valid else "FAILED",
            ok,
            len(mismatches),
            len(missing),
        )
        self.audit.record(
            "backup_verified" if valid else "backup_verification_failed",
            level="INFO" if valid else "ERROR",
            path=str(root),
            ok=ok,
            mismatches=len(mismatches),
            missing=len(missing),
        )
        return {
            "path": str(root),
            "valid": valid,
            "files_ok": ok,
            "mismatches": mismatches,
            "missing": missing,
            "rejected": rejected,
        }
