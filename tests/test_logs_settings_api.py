"""Real-time log stream (SSE), log export, storage report and temp purge."""

import json
import os

from app.graphene.installer import InstallSession
from app.logging_config import BOOT_ID, get_logger
from tests.conftest import POSIX_ONLY


def _token(client):
    return {"X-LMS-Token": client.get("/api/session").json()["csrf_token"]}


def _sse_events(text):
    events = []
    for block in text.split("\n\n"):
        fields = dict(line.split(": ", 1) for line in block.splitlines() if ": " in line and not line.startswith(":"))
        if fields.get("event") == "log":
            boot, _, entry_id = fields["id"].partition("-")
            data = json.loads(fields["data"])
            assert data["boot"] == boot == BOOT_ID
            events.append((int(entry_id), data))
    return events


def test_log_stream_sends_entries_with_ids(client):
    get_logger("test").info("stream marker one")
    response = client.get("/api/logs/stream?duration=1")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert response.headers["cache-control"] == "no-store"
    assert response.text.startswith("retry: 2000")
    events = _sse_events(response.text)
    assert any(entry["message"] == "stream marker one" for _, entry in events)
    assert all(event_id == entry["id"] for event_id, entry in events)


def test_log_stream_resumes_after_last_event_id(client):
    get_logger("test").info("before reconnect")
    last = client.get("/api/logs").json()["last_id"]
    get_logger("test").info("after reconnect")
    response = client.get("/api/logs/stream?duration=1", headers={"Last-Event-ID": f"{BOOT_ID}-{last}"})
    messages = [entry["message"] for _, entry in _sse_events(response.text)]
    assert "after reconnect" in messages and "before reconnect" not in messages


def test_log_stream_restarts_after_application_restart(client):
    """Ids from a previous launch (other boot id) must not hide the new entries."""
    get_logger("test").info("fresh launch entry")
    response = client.get("/api/logs/stream?duration=1", headers={"Last-Event-ID": "deadbeef-999999"})
    assert "fresh launch entry" in [entry["message"] for _, entry in _sse_events(response.text)]
    assert client.get("/api/logs").json()["boot"] == BOOT_ID


def test_log_stream_ends_when_server_stops(client):
    import time

    client.app.state.shutting_down.set()
    started = time.monotonic()
    response = client.get("/api/logs/stream?duration=600")
    assert response.status_code == 200 and time.monotonic() - started < 5


def test_log_stream_level_filter_and_validation(client):
    get_logger("test").info("info only")
    get_logger("test").error("an error line")
    events = _sse_events(client.get("/api/logs/stream?duration=1&level=ERROR").text)
    assert events and all(entry["level"] in {"ERROR", "CRIT"} for _, entry in events)
    assert client.get("/api/logs/stream?duration=0").status_code == 400
    assert client.get("/api/logs/stream?level=NOPE").status_code == 400


def test_log_stream_is_redacted(client):
    from app.logging_config import register_sensitive_value

    register_sensitive_value("SERIALSECRET42")
    get_logger("test").info("device SERIALSECRET42 attached")
    text = client.get("/api/logs/stream?duration=1").text
    assert "SERIALSECRET42" not in text


def test_log_export(client):
    get_logger("test").warning("export me")
    response = client.get("/api/logs/export")
    assert response.status_code == 200
    assert "attachment" in response.headers["content-disposition"]
    assert "WARN [lms.test] export me" in response.text


def test_storage_report(client, settings):
    (settings.downloads_dir / "x.bin").write_bytes(b"a" * 1000)
    data = client.get("/api/settings/storage").json()
    folders = {f["key"]: f for f in data["folders"]}
    assert set(folders) == {"downloads", "backups", "reports", "logs", "tmp"}
    assert folders["downloads"]["bytes"] >= 1000 and folders["downloads"]["files"] >= 1
    assert data["disk_free_bytes"] > 0


@POSIX_ONLY
def test_storage_report_does_not_follow_symlinks(client, settings, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "big.bin").write_bytes(b"b" * 50_000)
    os.symlink(outside, settings.temp_dir / "link")
    tmp = {f["key"]: f for f in client.get("/api/settings/storage").json()["folders"]}["tmp"]
    assert tmp["bytes"] < 50_000


def test_purge_requires_confirmation(client):
    assert client.post("/api/settings/purge-temp", json={}, headers=_token(client)).status_code == 400
    assert client.post("/api/settings/purge-temp", json={"confirm": False}, headers=_token(client)).status_code == 400
    assert client.post("/api/settings/purge-temp", json={"confirm": True}).status_code == 403  # no CSRF token


@POSIX_ONLY
def test_purge_removes_temp_content_only(client, settings, tmp_path):
    outside = tmp_path / "keep"
    outside.mkdir()
    (outside / "precious.txt").write_text("keep me")
    work = settings.temp_dir / "install-old"
    work.mkdir()
    (work / "image.zip").write_bytes(b"z" * 2000)
    (settings.temp_dir / "stray.tmp").write_bytes(b"s" * 10)
    os.symlink(outside, settings.temp_dir / "evil-link")
    result = client.post("/api/settings/purge-temp", json={"confirm": True}, headers=_token(client)).json()
    assert result["removed"] == 3 and result["errors"] == 0 and result["freed_bytes"] >= 2010
    assert settings.temp_dir.is_dir() and not any(settings.temp_dir.iterdir())
    assert (outside / "precious.txt").read_text() == "keep me"  # link removed, target untouched
    events = client.get("/api/audit").json()["events"]
    assert events[-1]["event"] == "temp_purged"


def test_purge_refused_while_install_step_runs(client, settings):
    installer = client.app.state.graphene.installer
    installer.session = InstallSession(
        id="a" * 32,
        device_id="d",
        serial_masked="x",
        codename="husky",
        model="Pixel 8 Pro",
        channel="stable",
        version="2026100200",
        confirmation_phrase="EFFACER HUSKY",
    )
    installer.session.busy = "flash"
    (settings.temp_dir / "install-live").mkdir()
    response = client.post("/api/settings/purge-temp", json={"confirm": True}, headers=_token(client))
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "install_busy"
    assert (settings.temp_dir / "install-live").is_dir()
