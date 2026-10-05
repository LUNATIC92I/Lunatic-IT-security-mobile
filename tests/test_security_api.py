import time

from tests.conftest import POSIX_ONLY

pytestmark = POSIX_ONLY

PIXEL = {"serial": "HUSKYSERIAL01", "state": "device", "profile": "pixel8pro_stock"}


def token(client):
    return {"X-LMS-Token": client.get("/api/session").json()["csrf_token"]}


def wait_scan(client, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = client.get("/api/security/scan").json()
        if status["state"] in ("completed", "failed"):
            return status
        time.sleep(0.1)
    raise AssertionError("scan did not finish")


def test_scan_flow(client, fake_devices):
    fake_devices(adb=[PIXEL])
    assert client.get("/api/security/scan").json()["state"] == "idle"
    assert client.post("/api/security/scan", json={}).status_code == 403  # CSRF
    response = client.post("/api/security/scan", json={}, headers=token(client))
    assert response.status_code == 202 and response.json()["state"] == "running"
    status = wait_scan(client)
    assert status["state"] == "completed"
    report = client.get("/api/security/report").json()
    assert report["report_id"] == status["report_id"] and 0 <= report["score"] <= 100
    assert "HUSKYSERIAL01" not in str(report)


def test_report_not_found(client, fake_devices):
    response = client.get("/api/security/report")
    assert response.status_code == 404 and response.json()["error"]["code"] == "report_not_found"


def test_scan_without_device(client, fake_devices):
    response = client.post("/api/security/scan", json={}, headers=token(client))
    assert response.status_code == 404 and response.json()["error"]["action"]


def test_scan_rejects_invalid_device_id(client, fake_devices):
    response = client.post("/api/security/scan", json={"device_id": "HUSKYSERIAL01"}, headers=token(client))
    assert response.status_code == 400


def test_live_sections(client, fake_devices):
    fake_devices(adb=[PIXEL])
    apps = client.get("/api/applications").json()
    assert apps["applications"]["third_party"] == 3
    perms = client.get("/api/permissions").json()
    assert perms["permissions"]["special_access"]["accessibility"] == ["com.example.flashlight"]
    assert all(not a["system"] for a in perms["apps"])
    assert client.get("/api/network").json()["network"]["proxy"] == "10.0.0.5:8080"
    assert client.get("/api/updates").json()["updates"]["security_patch"] == "2025-09-05"
    assert client.get("/api/security/boot").json()["boot"]["bootloader_locked"] is True
    assert client.get("/api/security/encryption").json()["encryption"]["state"] == "encrypted"
