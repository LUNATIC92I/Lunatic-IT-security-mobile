from tests.conftest import POSIX_ONLY

pytestmark = POSIX_ONLY

PIXEL = {"serial": "HUSKYSERIAL01", "state": "device", "profile": "pixel8pro_stock"}


def test_status_none(client, fake_devices):
    data = client.get("/api/device/status").json()
    assert data["summary"] == "none" and data["adb_available"] and data["fastboot_available"]


def test_details_flow(client, fake_devices):
    fake_devices(adb=[PIXEL])
    status = client.get("/api/device/status").json()
    device_id = status["devices"][0]["device_id"]
    details = client.get(f"/api/device?device_id={device_id}").json()
    assert details["model"] == "Pixel 8 Pro" and details["serial_masked"].startswith("HU")
    assert "HUSKYSERIAL01" not in str(details) and "HUSKYSERIAL01" not in str(status)
    assert client.get("/api/device").json()["device_id"] == device_id


def test_details_errors_are_friendly(client, fake_devices):
    response = client.get("/api/device")
    assert response.status_code == 404
    error = response.json()["error"]
    assert error["code"] == "device_not_found" and error["action"]
    fake_devices(adb=[{"serial": "ABCDEF1234", "state": "unauthorized"}])
    response = client.get("/api/device")
    assert response.status_code == 409 and response.json()["error"]["code"] == "device_not_ready"


def test_multiple_devices_conflict(client, fake_devices):
    fake_devices(adb=[PIXEL, {"serial": "OTHER00001", "state": "device", "profile": "samsung_old"}])
    response = client.get("/api/device")
    assert response.status_code == 409 and response.json()["error"]["code"] == "multiple_devices"


def test_device_id_validation(client, fake_devices):
    for bad in ("HUSKYSERIAL01", "../../etc", "0123456789ABCDEF", "x" * 16):
        response = client.get("/api/device", params={"device_id": bad})
        assert response.status_code == 400, bad


def test_restart_server_requires_csrf(client, fake_devices):
    assert client.post("/api/device/adb/restart-server").status_code == 403
    token = client.get("/api/session").json()["csrf_token"]
    response = client.post("/api/device/adb/restart-server", headers={"X-LMS-Token": token})
    assert response.status_code == 200 and response.json()["summary"] == "none"


def test_logs_mask_serial(client, fake_devices):
    fake_devices(adb=[PIXEL])
    client.get("/api/device/status")
    client.get("/api/device")
    logs = client.get("/api/logs").json()["entries"]
    text = " ".join(e["message"] for e in logs)
    assert "Device detected" in text and "Pixel model identified: Pixel 8 Pro (husky)" in text
    assert "HUSKYSERIAL01" not in text
