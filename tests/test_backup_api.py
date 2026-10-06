import time

from tests.conftest import POSIX_ONLY

pytestmark = POSIX_ONLY


def token(client):
    return {"X-LMS-Token": client.get("/api/session").json()["csrf_token"]}


def test_backup_flow(client, fake_devices, phone_storage, tmp_path):
    fake_devices(
        adb=[
            {
                "serial": "HUSKYSERIAL01",
                "state": "device",
                "profile": "pixel8pro_stock",
                "root": phone_storage["root"],
                "apks": phone_storage["apks"],
            }
        ]
    )
    dest = tmp_path / "dest"
    dest.mkdir()
    assert client.get("/api/backup/estimate").json()["third_party_apps"] == 3
    body = {"folders": ["DCIM", "Download"], "include_apks": False, "destination": str(dest)}
    assert client.post("/api/backup/start", json=body).status_code == 403  # CSRF
    response = client.post("/api/backup/start", json=body, headers=token(client))
    assert response.status_code == 202
    deadline = time.monotonic() + 30
    while client.get("/api/backup/status").json()["state"] == "running" and time.monotonic() < deadline:
        time.sleep(0.1)
    status = client.get("/api/backup/status").json()
    assert status["result"] == "verified"
    listing = client.get("/api/backup/list", params={"destination": str(dest)}).json()
    assert len(listing["backups"]) == 1
    verify = client.post("/api/backup/verify", json={"path": status["backup_path"]}, headers=token(client))
    assert verify.json()["valid"] is True


def test_backup_validation(client, fake_devices):
    for body in ({"folders": ["Android"]}, {"folders": ["../etc"]}, {"folders": [], "device_id": "SERIAL"}):
        response = client.post("/api/backup/start", json=body, headers=token(client))
        assert response.status_code == 400, body


def test_browse_home(client):
    data = client.get("/api/backup/browse").json()
    assert data["path"] and isinstance(data["directories"], list)
