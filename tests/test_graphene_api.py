import pytest

from app.graphene.releases import ReleaseClient
from tests.conftest import POSIX_ONLY
from tests.fakes.release_server import VERSION, FakeReleaseServer


@pytest.fixture
def api(client, settings):
    server = FakeReleaseServer()
    client.app.state.graphene.releases = ReleaseClient(settings, transport=server.transport())
    return client


def test_releases_catalog(api):
    data = api.get("/api/graphene/releases").json()
    assert data["source"] == "https://releases.grapheneos.org/overview.json"
    assert {d["codename"]: d["stable"] for d in data["devices"]}["husky"] == VERSION


def test_release_detail(api):
    data = api.get("/api/graphene/releases/husky", params={"channel": "beta"}).json()
    assert data["channel"] == "beta" and data["install_url"].startswith("https://releases.grapheneos.org/")


def test_release_validation(api):
    assert api.get("/api/graphene/releases/HUSKY").status_code in (400, 404)
    assert api.get("/api/graphene/releases/husky", params={"channel": "nightly"}).status_code == 400
    response = api.get("/api/graphene/releases/redfin")
    assert response.status_code == 404 and response.json()["error"]["code"] == "no_release"


@POSIX_ONLY
def test_compatibility_endpoint(api, fake_devices):
    fake_devices(adb=[{"serial": "HUSKYSERIAL01", "state": "device", "profile": "pixel8pro_unlocked"}])
    data = api.get("/api/graphene/compatibility").json()
    assert data["compatible"] is True and data["codename"] == "husky"
    assert {c["id"] for c in data["checks"]} >= {"model", "release", "unlock", "support", "fastboot", "disk"}


@POSIX_ONLY
def test_compatibility_without_device(api, fake_devices):
    response = api.get("/api/graphene/compatibility")
    assert response.status_code == 404 and response.json()["error"]["action"]
