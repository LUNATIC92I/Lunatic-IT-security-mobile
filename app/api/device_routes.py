"""Device detection API.

* ``GET  /api/device/status``              devices on ADB and Fastboot, with state guidance
* ``GET  /api/device``                     details of the selected (or only ready) device
* ``POST /api/device/adb/restart-server``  restart the local adb server (fixes most "offline" states)

``device_id`` is the opaque identifier returned by ``/api/device/status``;
serial numbers are never accepted from, nor returned to, the client.
"""

from __future__ import annotations

from fastapi import APIRouter, Query, Request

from app.models.device import DeviceDetails, DeviceStatus

router = APIRouter(prefix="/api/device", tags=["device"])

DEVICE_ID_QUERY = Query(None, pattern=r"^[0-9a-f]{16}$", description="Identifiant renvoyé par /api/device/status")


@router.get("/status", response_model=DeviceStatus)
def device_status(request: Request) -> DeviceStatus:
    return request.app.state.devices.status()


@router.get("", response_model=DeviceDetails)
def device_details(request: Request, device_id: str | None = DEVICE_ID_QUERY) -> DeviceDetails:
    return request.app.state.devices.details(device_id)


@router.post("/adb/restart-server", response_model=DeviceStatus)
def restart_adb_server(request: Request) -> DeviceStatus:
    return request.app.state.devices.restart_adb_server()
