import time

import pytest

from app.graphene import verifier
from app.graphene.downloader import DownloadManager
from app.graphene.releases import ReleaseClient
from tests.fakes.release_server import VERSION, FakeReleaseServer
from tests.fakes.signing import ReleaseSigner, install_zip


@pytest.fixture
def api(client, settings, monkeypatch):
    signer = ReleaseSigner()
    monkeypatch.setattr(verifier, "PINNED_KEY_B64", signer.b64)
    monkeypatch.setattr(verifier, "PINNED_FINGERPRINT", signer.fingerprint)
    server = FakeReleaseServer()
    data = install_zip("husky", VERSION)
    server.files = {
        f"husky-install-{VERSION}.zip": data,
        f"husky-install-{VERSION}.zip.sig": signer.sign(data),
        "allowed_signers": signer.allowed_signers(),
    }
    graphene = client.app.state.graphene
    transport = server.transport()
    graphene.releases = ReleaseClient(settings, transport=transport)
    graphene.downloads = DownloadManager(settings, graphene.releases, graphene.audit, transport=transport)
    return client


def token(client):
    return {"X-LMS-Token": client.get("/api/session").json()["csrf_token"]}


def wait(api):
    deadline = time.monotonic() + 20
    while api.get("/api/graphene/download/status").json()["state"] == "running" and time.monotonic() < deadline:
        time.sleep(0.05)
    return api.get("/api/graphene/download/status").json()


def test_download_flow(api):
    assert api.post("/api/graphene/download", json={"codename": "husky"}).status_code == 403  # CSRF
    response = api.post("/api/graphene/download", json={"codename": "husky", "channel": "stable"}, headers=token(api))
    assert response.status_code == 202
    status = wait(api)
    assert status["result"] == "ready" and status["verification"]["ok"]
    images = api.get("/api/graphene/images").json()["images"]
    assert images[0]["status"] == "ready"
    response = api.post("/api/graphene/verify", json={"codename": "husky", "version": VERSION}, headers=token(api))
    assert response.status_code == 202 and wait(api)["result"] == "ready"
    response = api.post(
        "/api/graphene/images/delete", json={"codename": "husky", "version": VERSION}, headers=token(api)
    )
    assert response.json() == {"deleted": True}


def test_client_cannot_choose_version_or_url(api, settings):
    for body in ({"codename": "../x"}, {"codename": "husky", "channel": "nightly"}):
        assert api.post("/api/graphene/download", json=body, headers=token(api)).status_code == 400
    # An injected URL is ignored: the image URL is always built from the official metadata.
    body = {"codename": "husky", "url": "https://evil.example/x.zip", "version": "1999010100"}
    assert api.post("/api/graphene/download", json=body, headers=token(api)).status_code == 202
    status = wait(api)
    assert status["version"] == VERSION and status["result"] == "ready"
    for body in ({"codename": "husky", "version": "1"}, {"codename": "husky", "version": "../../etc"}):
        assert api.post("/api/graphene/verify", json=body, headers=token(api)).status_code == 400


def test_unsupported_device(api):
    response = api.post("/api/graphene/download", json={"codename": "redfin"}, headers=token(api))
    assert response.status_code == 404 and response.json()["error"]["code"] == "no_release"
