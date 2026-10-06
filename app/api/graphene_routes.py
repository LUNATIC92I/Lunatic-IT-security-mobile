"""GrapheneOS API (phase 6: compatibility and official releases)."""

from __future__ import annotations

from fastapi import APIRouter, Path, Query, Request

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
