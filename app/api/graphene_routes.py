"""GrapheneOS API (phase 6: compatibility and official releases)."""

from __future__ import annotations

from fastapi import APIRouter, Path, Query, Request
from pydantic import BaseModel, Field

from app.models.graphene_release import CompatibilityResult, GrapheneRelease

router = APIRouter(prefix="/api/graphene", tags=["graphene"])

DEVICE_ID_QUERY = Query(None, pattern=r"^[0-9a-f]{16}$")
CHANNEL_QUERY = Query("stable", pattern=r"^(stable|beta|alpha)$")


@router.get("/compatibility", response_model=CompatibilityResult)
def compatibility(request: Request, device_id: str | None = DEVICE_ID_QUERY, channel: str = CHANNEL_QUERY):
    return request.app.state.graphene.compatibility(device_id, channel)


@router.get("/releases")
def releases(request: Request) -> dict:
    return request.app.state.graphene.catalog()


@router.get("/releases/{codename}", response_model=GrapheneRelease)
def release(request: Request, codename: str = Path(pattern=r"^[a-z][a-z0-9]{1,20}$"), channel: str = CHANNEL_QUERY):
    return request.app.state.graphene.release(codename, channel)


# ------------------------------------------------- phase 7: download + verify
CODENAME = r"^[a-z][a-z0-9]{1,20}$"


class DownloadRequest(BaseModel):
    codename: str = Field(pattern=CODENAME)
    channel: str = Field(default="stable", pattern=r"^(stable|beta|alpha)$")


class ImageRequest(BaseModel):
    codename: str = Field(pattern=CODENAME)
    version: str = Field(pattern=r"^\d{10}$")


def _downloads(request: Request):
    return request.app.state.graphene.downloads


@router.post("/download", status_code=202)
def download(request: Request, body: DownloadRequest) -> dict:
    """Download the official image for this device/channel (version chosen by the official server)."""
    return _downloads(request).start_download(body.codename, body.channel)


@router.get("/download/status")
def download_status(request: Request) -> dict:
    return _downloads(request).status()


@router.post("/download/cancel")
def download_cancel(request: Request) -> dict:
    return _downloads(request).cancel()


@router.post("/verify", status_code=202)
def verify(request: Request, body: ImageRequest) -> dict:
    """Re-run the full cryptographic verification of a downloaded image."""
    return _downloads(request).start_verify(body.codename, body.version)


@router.get("/images")
def images(request: Request) -> dict:
    return {"images": _downloads(request).list_images()}


@router.post("/images/delete")
def delete_image(request: Request, body: ImageRequest) -> dict:
    _downloads(request).delete_image(body.codename, body.version)
    return {"deleted": True}
