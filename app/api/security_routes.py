"""Security audit API.

Scan lifecycle:

* ``POST /api/security/scan``   start a full audit in the background
* ``GET  /api/security/scan``   progress of the current / last scan
* ``GET  /api/security/report`` latest report (per device, or by report id)

Live, read-only sections (each runs only the commands it needs):
``/api/applications``, ``/api/permissions``, ``/api/network``, ``/api/updates``,
``/api/security/boot``, ``/api/security/encryption``.
"""

from __future__ import annotations

from fastapi import APIRouter, Query, Request, status
from pydantic import BaseModel, Field

from app.models.security_report import SecurityReport

router = APIRouter(prefix="/api", tags=["security"])

DEVICE_ID_PATTERN = r"^[0-9a-f]{16}$"
DEVICE_ID_QUERY = Query(None, pattern=DEVICE_ID_PATTERN)


class ScanRequest(BaseModel):
    device_id: str | None = Field(default=None, pattern=DEVICE_ID_PATTERN)


def _scanner(request: Request):
    return request.app.state.scanner


@router.post("/security/scan", status_code=status.HTTP_202_ACCEPTED)
def start_scan(request: Request, body: ScanRequest) -> dict[str, object]:
    return _scanner(request).start_scan(body.device_id)


@router.get("/security/scan")
def scan_status(request: Request) -> dict[str, object]:
    return _scanner(request).status()


@router.get("/security/report", response_model=SecurityReport)
def security_report(
    request: Request,
    device_id: str | None = DEVICE_ID_QUERY,
    report_id: str | None = Query(None, pattern=r"^[0-9a-f]{12}$"),
) -> SecurityReport:
    return _scanner(request).report(device_id=device_id, report_id=report_id)


@router.get("/security/boot")
def boot(request: Request, device_id: str | None = DEVICE_ID_QUERY) -> dict[str, object]:
    section, findings, limitations = _scanner(request).boot_section(device_id)
    return {"boot": section, "findings": findings, "limitations": limitations}


@router.get("/security/encryption")
def encryption(request: Request, device_id: str | None = DEVICE_ID_QUERY) -> dict[str, object]:
    section, findings = _scanner(request).encryption_section(device_id)
    return {"encryption": section, "findings": findings}


@router.get("/applications")
def applications(request: Request, device_id: str | None = DEVICE_ID_QUERY) -> dict[str, object]:
    apps, _permissions, findings = _scanner(request).applications_section(device_id)
    return {"applications": apps, "findings": [f for f in findings if f.category.value == "applications"]}


@router.get("/permissions")
def permissions(request: Request, device_id: str | None = DEVICE_ID_QUERY) -> dict[str, object]:
    apps, perms, findings = _scanner(request).applications_section(device_id)
    risky = [a for a in apps.apps if not a.system and (a.granted_groups or a.special_access)]
    return {
        "permissions": perms,
        "apps": risky,
        "findings": [f for f in findings if f.category.value == "permissions"],
    }


@router.get("/network")
def network(request: Request, device_id: str | None = DEVICE_ID_QUERY) -> dict[str, object]:
    section, findings, limitations = _scanner(request).network_section(device_id)
    return {"network": section, "findings": findings, "limitations": limitations}


@router.get("/updates")
def updates(request: Request, device_id: str | None = DEVICE_ID_QUERY) -> dict[str, object]:
    section, findings = _scanner(request).updates_section(device_id)
    return {"updates": section, "findings": findings}
