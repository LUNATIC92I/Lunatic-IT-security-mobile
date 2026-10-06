from tests.conftest import POSIX_ONLY

pytestmark = POSIX_ONLY

PIXEL = {"serial": "HUSKYSERIAL01", "state": "device", "profile": "pixel8pro_stock"}


def token(client):
    return {"X-LMS-Token": client.get("/api/session").json()["csrf_token"]}


def body(item, **extra):
    return {
        "action_id": item["action_id"],
        "target": item["target"],
        "plan_token": item["plan_token"],
        "issued_at": item["issued_at"],
        "confirm": True,
        **extra,
    }


def test_plan_and_apply(client, fake_devices):
    fake_devices(adb=[PIXEL])
    plan = client.get("/api/hardening/plan").json()
    item = next(i for i in plan["actions"] if i["action_id"] == "enable_private_dns")
    assert client.post("/api/hardening/apply", json=body(item)).status_code == 403  # CSRF
    response = client.post("/api/hardening/apply", json=body(item), headers=token(client))
    assert response.status_code == 200 and response.json()["status"] == "verified"


def test_confirmation_is_mandatory(client, fake_devices):
    fake_devices(adb=[PIXEL])
    item = client.get("/api/hardening/plan").json()["actions"][0]
    for payload in (body(item, confirm=False), {k: v for k, v in body(item).items() if k != "confirm"}):
        response = client.post("/api/hardening/apply", json=payload, headers=token(client))
        assert response.status_code == 400


def test_invalid_payloads(client, fake_devices):
    fake_devices(adb=[PIXEL])
    item = client.get("/api/hardening/plan").json()["actions"][0]
    for bad in ({"target": "a;reboot"}, {"action_id": "../x"}, {"plan_token": "zz"}, {"device_id": "HUSKY"}):
        response = client.post("/api/hardening/apply", json=body(item, **bad), headers=token(client))
        assert response.status_code == 400, bad


def test_state_changed_is_409(client, fake_devices):
    fake_devices(adb=[PIXEL])
    item = next(
        i for i in client.get("/api/hardening/plan").json()["actions"] if i["action_id"] == "clear_global_proxy"
    )
    response = client.post("/api/hardening/apply", json=body(item, plan_token="0" * 64), headers=token(client))
    assert response.status_code == 409 and response.json()["error"]["code"] == "hardening_state_changed"
