"""Security hardening API.

* ``GET  /api/hardening/plan``   actions applicable now (BEFORE / AFTER / RISK) + manual checklist
* ``POST /api/hardening/apply``  apply ONE action; requires ``confirm: true`` and the signed plan token

Server-side guarantees: the action must exist, its target must be valid and
still applicable, the before-state must be exactly the one the user saw (token),
and the result is reported ``verified`` only after a second read on the phone.
"""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/hardening", tags=["hardening"])

DEVICE_ID_PATTERN = r"^[0-9a-f]{16}$"


class ApplyRequest(BaseModel):
    device_id: str | None = Field(default=None, pattern=DEVICE_ID_PATTERN)
    action_id: str = Field(pattern=r"^[a-z_]{3,40}$")
    target: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.:]{1,200}$")
    plan_token: str = Field(pattern=r"^[0-9a-f]{64}$")
    issued_at: int = Field(ge=0)
    confirm: Literal[True] = Field(description="Confirmation explicite de l'utilisateur")


@router.get("/plan")
def hardening_plan(request: Request, device_id: str | None = Query(None, pattern=DEVICE_ID_PATTERN)) -> dict:
    return request.app.state.hardening.plan(device_id)


@router.post("/apply")
def hardening_apply(request: Request, body: ApplyRequest) -> dict:
    return request.app.state.hardening.apply(
        body.device_id, body.action_id, body.target, body.plan_token, body.issued_at
    )
