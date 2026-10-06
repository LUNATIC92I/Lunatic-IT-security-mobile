import dataclasses
import json
import time

import pytest

from app.core import platform_tools
from app.core.audit_logger import AuditLogger
from app.core.device_manager import DeviceManager
from app.core.errors import CommandNotAllowedError, InvalidInputError, ScanInProgressError, ToolExecutionError
from app.core.hardening_service import HardeningService
from app.core.platform_tools import Arg, CommandRunner
from app.core.security_scanner import SecurityScanner
from app.security import hardening
from app.security.hardening import HardeningNotApplicableError, HardeningStateChangedError, parse_account_types
from tests.conftest import POSIX_ONLY

pytestmark = POSIX_ONLY


def device(profile="pixel8pro_stock", **extra):
    return {"serial": "HUSKYSERIAL01", "state": "device", "profile": profile, **extra}


@pytest.fixture
def service(settings):
    settings.ensure_directories()
    audit = AuditLogger(settings.audit_log_path)
    return HardeningService(SecurityScanner(settings, DeviceManager(CommandRunner(settings), audit), audit), audit)


def find(plan, action_id, target=None):
    return next(i for i in plan["actions"] if i["action_id"] == action_id and i["target"] == target)


def apply(service, item, **override):
    args = {
        "action_id": item["action_id"],
        "target": item["target"],
        "token": item["plan_token"],
        "issued": item["issued_at"],
        **override,
    }
    return service.apply(None, args["action_id"], args["target"], args["token"], args["issued"])


def test_plan_for_suspicious_device(service, fake_devices):
    fake_devices(adb=[device()])
    plan = service.plan(None)
    ids = [(i["action_id"], i["target"]) for i in plan["actions"]]
    assert ("disable_accessibility", "com.example.flashlight") in ids
    assert ("unknown_sources", "org.mozilla.firefox") in ids
    assert ("revoke_permission", "com.example.flashlight:sms") in ids
    assert ("clear_global_proxy", None) in ids and ("enable_private_dns", None) in ids
    assert ids[-1] == ("disable_usb_debugging", None)  # always last
    for item in plan["actions"]:
        assert item["before"] and item["after"] and item["risk"] and item["revert"]
        assert len(item["plan_token"]) == 64
    # Low-risk apps (whatsapp) are not proposed for permission removal.
    assert not any(t and t.startswith("com.whatsapp") for _a, t in ids)
    assert plan["serial_masked"].startswith("HU") and "HUSKYSERIAL01" not in json.dumps(plan)


def test_plan_for_clean_device(service, fake_devices):
    fake_devices(adb=[device("grapheneos")])
    plan = service.plan(None)
    assert [i["action_id"] for i in plan["actions"]] == ["disable_usb_debugging"]
    checklist = {c["id"]: c for c in plan["checklist"]}
    assert checklist["patch"]["status"] == "ok" and checklist["bootloader"]["status"] == "ok"


def test_accounts_types_only(service, fake_devices):
    fake_devices(adb=[device()])
    plan = service.plan(None)
    text = json.dumps(plan)
    assert "jean.dupont@gmail.com" not in text and "work@corp.example" not in text
    accounts = next(c for c in plan["checklist"] if c["id"] == "accounts")
    assert "com.google ×2" in accounts["detail"]
    assert parse_account_types(
        "Account {name=a@b.c, type=com.google}\n  Active Sessions: 1\nAccount {name=x, type=com.evil}"
    ) == ["com.google"]


def test_apply_is_verified_and_audited(service, fake_devices):
    fake_devices(adb=[device()])
    item = find(service.plan(None), "clear_global_proxy")
    result = apply(service, item)
    assert result["status"] == "verified" and result["after_observed"] == "settings global http_proxy = :0"
    assert result["before"] == "Proxy HTTP global : 10.0.0.5:8080"
    events = [e["event"] for e in service.audit.read()]
    assert events[-2:] == ["hardening_requested", "hardening_verified"]
    # Re-planning: the action is no longer proposed.
    assert not any(i["action_id"] == "clear_global_proxy" for i in service.plan(None)["actions"])


def test_apply_twice_is_refused(service, fake_devices):
    fake_devices(adb=[device()])
    item = find(service.plan(None), "enable_private_dns")
    apply(service, item)
    with pytest.raises(HardeningNotApplicableError):
        apply(service, item)


def test_token_tampering_and_expiry(service, fake_devices):
    fake_devices(adb=[device()])
    plan = service.plan(None)
    item = find(plan, "unknown_sources", "org.mozilla.firefox")
    with pytest.raises(HardeningStateChangedError):
        apply(service, item, token="0" * 64)
    with pytest.raises(HardeningStateChangedError):  # token bound to its target
        apply(service, item, target="com.example.flashlight")
    with pytest.raises(HardeningStateChangedError):
        apply(service, item, issued=item["issued_at"] - 1)
    old = int(time.time()) - hardening.TOKEN_TTL_SECONDS - 5
    stale = service.engine.signer.sign(plan["device_id"], item["action_id"], item["target"], item["before"], old)
    with pytest.raises(HardeningStateChangedError):
        apply(service, item, token=stale, issued=old)


def test_state_changed_since_plan(service, fake_devices, tmp_path):
    fake_devices(adb=[device()])
    item = find(service.plan(None), "disable_accessibility", "com.example.flashlight")
    # Another app gets an accessibility service on the phone meanwhile -> the "before" text changes.
    state_file = tmp_path / "fake-devices.state.json"
    state_file.write_text(
        json.dumps(
            {
                "HUSKYSERIAL01": {
                    "global": {},
                    "secure": {
                        "enabled_accessibility_services": "com.example.flashlight/com.example.flashlight.Svc:com.example.flashlight/.Other"
                    },
                    "deleted": [],
                    "install_denied": [],
                    "revoked": {},
                }
            }
        )
    )
    with pytest.raises(HardeningStateChangedError):
        apply(service, item)


def test_accessibility_keeps_other_services(service, fake_devices, tmp_path):
    fake_devices(adb=[device()])
    (tmp_path / "fake-devices.state.json").write_text(
        json.dumps(
            {
                "HUSKYSERIAL01": {
                    "global": {},
                    "secure": {
                        "enabled_accessibility_services": "com.example.flashlight/com.example.flashlight.Svc:com.google.android.marvin.talkback/"
                        "com.google.android.marvin.talkback.TalkBackService"
                    },
                    "deleted": [],
                    "install_denied": [],
                    "revoked": {},
                }
            }
        )
    )
    item = find(service.plan(None), "disable_accessibility", "com.example.flashlight")
    result = apply(service, item)
    assert result["status"] == "verified"
    assert "talkback" in result["after_observed"] and "flashlight" not in result["after_observed"]


def test_revoke_permission_group(service, fake_devices, tmp_path, monkeypatch):
    log = tmp_path / "calls.jsonl"
    monkeypatch.setenv("LMS_FAKE_CALL_LOG", str(log))
    fake_devices(adb=[device()])
    item = find(service.plan(None), "revoke_permission", "com.example.flashlight:sms")
    assert apply(service, item)["status"] == "verified"
    revokes = [c["args"][-2:] for c in map(json.loads, log.read_text().splitlines()) if "revoke" in c["args"]]
    assert revokes == [
        ["com.example.flashlight", "android.permission.READ_SMS"],
        ["com.example.flashlight", "android.permission.RECEIVE_SMS"],
    ]


def test_ignored_change_is_never_reported_as_success(service, fake_devices):
    fake_devices(adb=[device(revoke_ignored=True)])
    item = find(service.plan(None), "revoke_permission", "com.example.flashlight:camera")
    result = apply(service, item)
    assert result["status"] == "not_verified" and "CAMERA" in result["after_observed"]
    assert service.audit.read()[-1]["event"] == "hardening_not_verified"


def test_phone_refusing_change(service, fake_devices):
    fake_devices(adb=[device(refuse_changes=True)])
    item = find(service.plan(None), "clear_global_proxy")
    with pytest.raises(ToolExecutionError) as exc:
        apply(service, item)
    assert "refusé" in exc.value.message and "SecurityException" in exc.value.detail
    assert service.audit.read()[-1]["event"] == "hardening_failed"


def test_disable_usb_debugging_verified_by_disappearance(service, fake_devices):
    fake_devices(adb=[device()])
    item = find(service.plan(None), "disable_usb_debugging")
    assert item["ends_adb_session"] is True
    result = apply(service, item)
    assert result["status"] == "verified" and "débogage USB est coupé" in result["after_observed"]
    assert service.scanner.devices.status().summary == "none"


def test_refused_during_scan(service, fake_devices, monkeypatch):
    fake_devices(adb=[device()])
    item = find(service.plan(None), "enable_private_dns")
    monkeypatch.setattr(service.scanner, "status", lambda: {"state": "running"})
    with pytest.raises(ScanInProgressError):
        apply(service, item)


def test_unknown_action_and_bad_target(service, fake_devices):
    fake_devices(adb=[device()])
    with pytest.raises(InvalidInputError):
        service.apply(None, "rm_rf", None, "0" * 64, int(time.time()))
    with pytest.raises(InvalidInputError):
        service.apply(None, "revoke_permission", "com.x:notagroup", "0" * 64, int(time.time()))


def test_runner_requires_confirmation_for_mutations(settings, fake_devices):
    fake_devices(adb=[device()])
    with pytest.raises(CommandNotAllowedError):
        CommandRunner(settings).run("adb.clear_global_proxy", serial="HUSKYSERIAL01")


@pytest.mark.parametrize("value", ["a;reboot", "a b", "a$(id)", "a`id`", "a|b", "a&b", "a>b", "a'b", 'a"b', "a\\b"])
def test_device_shell_metacharacters_rejected(value):
    permissive = Arg("x", r".+")
    with pytest.raises(InvalidInputError):
        permissive.validate(value)


def test_every_mutating_command_is_flagged():
    for spec in platform_tools.COMMAND_WHITELIST.values():
        words = {p for p in spec.template if isinstance(p, str)}
        if words & {"put", "delete", "revoke"} or (spec.template[:2] == ("shell", "appops") and "set" in words):
            assert spec.mutating, spec.name


def test_component_list_cannot_inject(settings, fake_devices):
    fake_devices(adb=[device()])
    spec = platform_tools.COMMAND_WHITELIST["adb.accessibility_set"]
    with pytest.raises(InvalidInputError):
        spec.build("HUSKYSERIAL01", {"components": "a.b/.C;reboot"})
    with pytest.raises(InvalidInputError):
        spec.build("HUSKYSERIAL01", {"components": "a.b/C$Inner"})
    assert dataclasses.replace(spec).mutating


@pytest.mark.parametrize(
    ("action_id", "target", "failing"),
    [
        ("clear_global_proxy", None, "adb.settings_get"),
        ("revoke_permission", "com.example.flashlight:camera", "adb.dumpsys_package_one"),
    ],
)
def test_unreadable_phone_after_change_is_not_verified(service, fake_devices, monkeypatch, action_id, target, failing):
    """A read-back that fails must never be mistaken for the expected state."""
    from app.core.errors import ToolTimeoutError

    fake_devices(adb=[device()])
    item = find(service.plan(None), action_id, target)
    original = CommandRunner.run
    changed = {"done": False}

    def flaky(self, command, *args, **kwargs):
        if kwargs.get("confirmed"):
            changed["done"] = True
        elif changed["done"] and command == failing:
            raise ToolTimeoutError(detail="simulated: phone stopped answering")
        return original(self, command, *args, **kwargs)

    monkeypatch.setattr(CommandRunner, "run", flaky)
    result = apply(service, item)
    assert result["status"] == "not_verified"
    assert "Relecture impossible" in result["after_observed"]
