"""Backup API.

* ``GET  /api/backup/estimate``  size of each shared folder + what cannot be backed up
* ``GET  /api/backup/browse``    sub-directories of a local folder (destination picker)
* ``POST /api/backup/start``     start a backup (folders, APKs, destination)
* ``GET  /api/backup/status``    progress / result of the current or last backup
* ``POST /api/backup/cancel``    cancel the running backup (partial files removed)
* ``GET  /api/backup/list``      backups found in a destination folder
* ``POST /api/backup/verify``    re-check an existing backup against its SHA256SUMS
"""

from __future__ import annotations

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, Field

from app.core.platform_tools import SHARED_FOLDERS

router = APIRouter(prefix="/api/backup", tags=["backup"])

DEVICE_ID_PATTERN = r"^[0-9a-f]{16}$"
FOLDER_PATTERN = "^(?:" + "|".join(SHARED_FOLDERS) + ")$"


class StartRequest(BaseModel):
    device_id: str | None = Field(default=None, pattern=DEVICE_ID_PATTERN)
    folders: list[str] = Field(default_factory=list, max_length=len(SHARED_FOLDERS))
    include_apks: bool = False
    destination: str | None = Field(default=None, max_length=4096)

    def model_post_init(self, _context) -> None:
        import re

        for folder in self.folders:
            if not re.fullmatch(FOLDER_PATTERN, folder):
                raise ValueError(f"unknown folder {folder!r}")


class VerifyRequest(BaseModel):
    path: str = Field(min_length=1, max_length=4096)


def _backup(request: Request):
    return request.app.state.backup


@router.get("/estimate")
def estimate(request: Request, device_id: str | None = Query(None, pattern=DEVICE_ID_PATTERN)) -> dict:
    return _backup(request).estimate(device_id)


@router.get("/browse")
def browse(request: Request, path: str | None = Query(None, max_length=4096)) -> dict:
    return _backup(request).browse(path)


@router.post("/start", status_code=202)
def start(request: Request, body: StartRequest) -> dict:
    return _backup(request).start(body.device_id, body.folders, body.include_apks, body.destination)


@router.get("/status")
def status(request: Request) -> dict:
    return _backup(request).status()


@router.post("/cancel")
def cancel(request: Request) -> dict:
    return _backup(request).cancel()


@router.get("/list")
def list_backups(request: Request, destination: str | None = Query(None, max_length=4096)) -> dict:
    return _backup(request).list_backups(destination)


@router.post("/verify")
def verify(request: Request, body: VerifyRequest) -> dict:
    return _backup(request).verify_backup(body.path)
