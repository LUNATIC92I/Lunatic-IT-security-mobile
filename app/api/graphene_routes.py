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


# ------------------------------------------------- phase 8: installation wizard
SESSION_ID = Field(pattern=r"^[0-9a-f]{32}$")
INSTALL_ACTIONS = {
    "tools": "check_tools",
    "reboot_bootloader": "reboot_to_bootloader",
    "unlock": "unlock_bootloader",
    "prepare_image": "prepare_image",
    "preflight": "preflight",
    "flash": "flash",
    "verify_result": "verify_result",
    "lock": "lock_bootloader",
    "reboot": "reboot",
    "post_check": "post_check",
}
DESTRUCTIVE_ACTIONS = {"reboot_bootloader", "unlock", "flash", "lock", "reboot"}


class InstallStartRequest(BaseModel):
    device_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{16}$")
    channel: str = Field(default="stable", pattern=r"^(stable|beta|alpha)$")


class InstallConfirmRequest(BaseModel):
    session_id: str = SESSION_ID
    phrase: str = Field(max_length=60)
    data_loss_ack: bool
    backup_ack: bool


class InstallActionRequest(BaseModel):
    session_id: str = SESSION_ID
    action: str = Field(pattern="^(" + "|".join(INSTALL_ACTIONS) + ")$")
    confirm: bool = False


class InstallSessionRequest(BaseModel):
    session_id: str = SESSION_ID


def _installer(request: Request):
    return request.app.state.graphene.installer


@router.post("/install")
def install_start(request: Request, body: InstallStartRequest) -> dict:
    """Steps 1-4: detect, check compatibility, open an installation session with the wipe warning."""
    return _installer(request).start(body.device_id, body.channel)


@router.post("/install/confirm")
def install_confirm(request: Request, body: InstallConfirmRequest) -> dict:
    return _installer(request).confirm(body.session_id, body.phrase, body.data_loss_ack, body.backup_ack)


@router.post("/install/action")
def install_action(request: Request, body: InstallActionRequest) -> dict:
    if body.action in DESTRUCTIVE_ACTIONS and not body.confirm:
        from app.core.errors import InvalidInputError

        raise InvalidInputError(
            "Confirmation requise.",
            cause="Cette étape agit sur le téléphone (redémarrage, effacement ou flashage).",
            action="Confirmez l'opération dans la fenêtre de confirmation.",
        )
    return getattr(_installer(request), INSTALL_ACTIONS[body.action])(body.session_id)


@router.get("/install/status")
def install_status(request: Request) -> dict:
    return _installer(request).status()


@router.post("/install/abandon")
def install_abandon(request: Request, body: InstallSessionRequest) -> dict:
    return _installer(request).abandon(body.session_id)
