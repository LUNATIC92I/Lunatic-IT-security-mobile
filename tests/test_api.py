from fastapi.testclient import TestClient

from app.api import routes
from app.main import create_app
from tests.conftest import POSIX_ONLY


def test_health(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.headers["cache-control"] == "no-store"


def test_security_headers_on_frontend(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "LUNATIC" in response.text
    csp = response.headers["content-security-policy"]
    assert "default-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert response.headers["x-frame-options"] == "DENY"


def test_frontend_assets_served(client):
    for path in ("/css/main.css", "/css/dashboard.css", "/js/app.js"):
        assert client.get(path).status_code == 200


def test_foreign_host_rejected(settings):
    client = TestClient(create_app(settings, console_logging=False), base_url="http://evil.example.com")
    assert client.get("/api/health").status_code == 400


def test_post_without_token_rejected(client):
    response = client.post("/api/health")
    assert response.status_code == 403
    body = response.json()["error"]
    assert body["code"] == "request_rejected" and body["cause"] and body["action"]


def test_post_with_foreign_origin_rejected(client):
    token = client.get("/api/session").json()["csrf_token"]
    response = client.post("/api/health", headers={"X-LMS-Token": token, "Origin": "https://evil.example.com"})
    assert response.status_code == 403


def test_post_with_valid_token_passes_csrf(client, settings):
    token = client.get("/api/session").json()["csrf_token"]
    response = client.post("/api/health", headers={"X-LMS-Token": token, "Origin": f"http://127.0.0.1:{settings.port}"})
    assert response.status_code == 405  # reached routing: no POST handler on /api/health


@POSIX_ONLY
def test_environment_endpoint(client):
    data = client.get("/api/system/environment").json()
    assert data["tools"]["adb"]["version"] == "35.0.2-12147458"
    assert {c["id"] for c in data["checks"]} >= {"python", "data_dir", "disk", "adb", "fastboot"}


def test_logs_endpoint_polling(client):
    client.get("/api/system/environment")
    first = client.get("/api/logs").json()
    assert first["entries"]
    again = client.get(f"/api/logs?since={first['last_id']}").json()
    assert all(e["id"] > first["last_id"] for e in again["entries"])


def test_logs_endpoint_validation_error_is_friendly(client):
    response = client.get("/api/logs?level=NOPE")
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_input"


def test_audit_endpoints(client):
    events = client.get("/api/audit").json()["events"]
    assert events[-1]["event"] == "application_started"
    assert client.get("/api/audit/verify").json()["valid"] is True


def test_settings_endpoint(client):
    data = client.get("/api/settings").json()
    assert data["host"] == "127.0.0.1"
    assert data["grapheneos_releases_url"] == "https://releases.grapheneos.org"


def test_unexpected_exception_not_leaked(settings, monkeypatch):
    def boom(*_args):
        raise RuntimeError("internal secret path /root/x")

    monkeypatch.setattr(routes, "collect_environment", boom)
    client = TestClient(
        create_app(settings, console_logging=False), base_url="http://127.0.0.1", raise_server_exceptions=False
    )
    response = client.get("/api/system/environment")
    assert response.status_code == 500
    error = response.json()["error"]
    assert "secret" not in str(error) and error["message"] and error["action"]


def test_non_ascii_token_is_rejected_not_crashing(client):
    response = client.post("/api/health", headers={"X-LMS-Token": "jeton-é".encode()})
    assert response.status_code == 403


def test_backup_listing_does_not_write(client, tmp_path):
    folder = tmp_path / "listing"
    folder.mkdir()
    response = client.get("/api/backup/list", params={"destination": str(folder)})
    assert response.status_code == 200
    assert not any(folder.iterdir())  # a GET never creates a write-test file


def test_cross_site_get_rejected(client):
    """A web page cannot make the app query the phone, even with a blind GET (<img src=...>)."""
    assert client.get("/api/device/status", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert client.get("/api/health", headers={"Sec-Fetch-Site": "same-origin"}).status_code == 200
    assert client.get("/", headers={"Sec-Fetch-Site": "none"}).status_code == 200
