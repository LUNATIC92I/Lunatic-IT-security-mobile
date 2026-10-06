from datetime import date

import pytest

from app.config import Settings
from app.core.audit_logger import AuditLogger
from app.core.device_manager import DeviceManager
from app.core.errors import InvalidInputError
from app.core.grapheneos_manager import GrapheneOSManager, parse_unlock_ability
from app.core.platform_tools import CommandRunner, Tool, inspect_tool
from app.graphene import compatibility
from app.graphene.compatibility import SUPPORTED_DEVICES, device_checks, months_until
from app.graphene.releases import (
    NoReleaseError,
    ReleaseClient,
    ReleaseServerError,
    parse_channel_metadata,
    parse_overview,
    validate_codename,
)
from tests.conftest import POSIX_ONLY
from tests.fakes.release_server import VERSION, FakeReleaseServer


@pytest.fixture
def server():
    return FakeReleaseServer()


@pytest.fixture
def client(server, settings):
    return ReleaseClient(settings, transport=server.transport())


# ---------------------------------------------------------------- parsing
def test_parse_channel_metadata():
    assert parse_channel_metadata("2026100200 1790926302 husky stable\n", "husky", "stable") == (
        "2026100200",
        1790926302,
    )
    for bad in (
        "2026100200 1790926302 shiba stable",
        "2026100200 1790926302 husky beta",
        "abc 1 husky stable",
        "<html>error</html>",
        "",
    ):
        with pytest.raises(ReleaseServerError):
            parse_channel_metadata(bad, "husky", "stable")


def test_parse_overview_filters_garbage():
    data = {"husky": {"stable": VERSION, "evil": "x", "beta": "../../"}, "Bad Name": {}, "shiba": "nope"}
    assert parse_overview(data) == {"husky": {"stable": VERSION}}
    with pytest.raises(ReleaseServerError):
        parse_overview([1, 2])


@pytest.mark.parametrize("value", ["../etc", "HUSKY", "husky/../x", "a", "husky stable", "x" * 40])
def test_codename_validation(value):
    with pytest.raises(InvalidInputError):
        validate_codename(value)


def test_unlock_ability_parsing():
    assert parse_unlock_ability("(bootloader) get_unlock_ability: 1\nOKAY") is True
    assert parse_unlock_ability("(bootloader) get_unlock_ability: 0") is False
    assert parse_unlock_ability("FAILED (remote: 'unknown command')") is None


def test_catalog_matches_official_list():
    assert len(SUPPORTED_DEVICES) == 21
    assert SUPPORTED_DEVICES["husky"].model == "Pixel 8 Pro"
    assert "redfin" not in SUPPORTED_DEVICES and "redfin" in compatibility.END_OF_LIFE


def test_months_until():
    assert months_until("2026-10", date(2026, 10, 6)) == 0
    assert months_until("2033-03", date(2026, 10, 6)) == 77
    assert months_until("2026-05", date(2026, 10, 6)) == -5


# ---------------------------------------------------------------- client
def test_release_details(client, server):
    release = client.release("husky", "stable")
    assert release.version == VERSION and release.build_date == "2026-10-02"
    assert release.install_url == "https://releases.grapheneos.org/husky-install-2026100200.zip"
    assert release.signature_url.endswith(".zip.sig") and release.allowed_signers_url.endswith("/allowed_signers")
    assert release.size_bytes == 1873867524
    assert all("releases.grapheneos.org" in r for r in server.requests)


def test_release_errors(client, server):
    with pytest.raises(NoReleaseError):
        client.release("oriole", "alpha")
    with pytest.raises(NoReleaseError):
        client.release("redfin", "stable")  # end-of-life: not even requested
    server.status_override = 500
    with pytest.raises(ReleaseServerError):
        client.release("husky", "stable")
    server.status_override = None
    server.redirect = True
    with pytest.raises(ReleaseServerError):
        client.release("husky", "stable")
    server.redirect = False
    server.huge = True
    with pytest.raises(ReleaseServerError) as exc:
        client.release("husky", "stable")
    assert "too large" in exc.value.detail
    server.huge = False
    server.down = True
    with pytest.raises(ReleaseServerError) as exc:
        client.overview(force=True)
    assert exc.value.action


def test_overview_cache(client, server):
    client.overview()
    client.overview()
    assert sum("overview.json" in r for r in server.requests) == 1
    client.overview(force=True)
    assert sum("overview.json" in r for r in server.requests) == 2


def test_official_endpoint_is_enforced():
    with pytest.raises(ValueError):
        Settings(grapheneos_releases_url="https://releases.evil.example", _env_file=None)


# ---------------------------------------------------------- device checks
def base_kwargs(**overrides):
    kwargs = dict(
        codename="husky",
        manufacturer="Google",
        model="Pixel 8 Pro",
        transport="adb",
        release_version=VERSION,
        release_error=None,
        release_missing=False,
        channel="stable",
        oem_unlock_supported=True,
        oem_unlock_allowed=True,
        unlock_ability=None,
        bootloader_locked=True,
        verified_boot_state="green",
        today=date(2026, 10, 6),
    )
    kwargs.update(overrides)
    return kwargs


def by_id(checks):
    return {c.id: c for c in checks}


def test_checks_supported_pixel():
    checks = by_id(device_checks(**base_kwargs()))
    assert checks["model"].status == checks["release"].status == checks["unlock"].status == "ok"
    assert checks["support"].status == "ok"


def test_checks_oem_unlock_disabled_gives_instructions():
    checks = by_id(device_checks(**base_kwargs(oem_unlock_allowed=False)))
    assert checks["unlock"].status == "warn" and "Déverrouillage OEM" in checks["unlock"].action
    assert "contournera" not in checks["unlock"].action or "opérateur" in checks["unlock"].action


def test_checks_unlock_not_supported():
    checks = by_id(device_checks(**base_kwargs(oem_unlock_allowed=False, oem_unlock_supported=False)))
    assert checks["unlock"].status == "fail" and "ne contournera pas" in checks["unlock"].action


def test_checks_fastboot_unlock_ability():
    assert by_id(device_checks(**base_kwargs(transport="fastboot", unlock_ability=False)))["unlock"].status == "fail"
    assert by_id(device_checks(**base_kwargs(transport="fastboot", unlock_ability=True)))["unlock"].status == "ok"
    already = device_checks(**base_kwargs(transport="fastboot", unlock_ability=False, bootloader_locked=False))
    assert by_id(already)["unlock"].status == "ok"


def test_checks_non_pixel_and_eol():
    samsung = device_checks(**base_kwargs(codename="a51", manufacturer="samsung", model="SM-A515F"))
    assert [c.id for c in samsung] == ["model"] and samsung[0].status == "fail"
    eol = by_id(device_checks(**base_kwargs(codename="redfin", model="Pixel 5")))
    assert eol["model"].status == "fail" and "fin de vie" in eol["model"].detail


def test_checks_release_states():
    assert by_id(device_checks(**base_kwargs(release_version=None, release_missing=True)))["release"].status == "fail"
    unreachable = by_id(device_checks(**base_kwargs(release_version=None, release_error="timeout")))
    assert unreachable["release"].status == "warn"


def test_checks_end_of_support_and_current_os():
    oriole = by_id(device_checks(**base_kwargs(codename="oriole", model="Pixel 6")))
    assert oriole["support"].status == "warn"
    graphene = by_id(device_checks(**base_kwargs(verified_boot_state="yellow")))
    assert graphene["current_os"].status == "info"


# ------------------------------------------------------------ end-to-end
@pytest.fixture
def manager(settings, server, tmp_path):
    settings.ensure_directories()
    audit = AuditLogger(settings.audit_log_path)
    return GrapheneOSManager(
        settings,
        DeviceManager(CommandRunner(settings), audit),
        audit,
        releases=ReleaseClient(settings, transport=server.transport()),
    )


@POSIX_ONLY
def test_compatibility_adb_pixel(manager, fake_devices, monkeypatch):
    monkeypatch.setattr(compatibility, "MIN_FREE_DISK_BYTES", 1)
    fake_devices(adb=[{"serial": "HUSKYSERIAL01", "state": "device", "profile": "pixel8pro_stock"}])
    result = manager.compatibility(None)
    assert result.compatible and result.ready_to_prepare
    assert result.codename == "husky" and result.release.version == VERSION
    assert by_id(result.checks)["unlock"].status == "warn"  # OEM unlocking still disabled in the profile
    assert "HUSKYSERIAL01" not in result.model_dump_json()
    assert manager.audit.read()[-1]["event"] == "graphene_compatibility_checked"


@POSIX_ONLY
def test_compatibility_non_pixel(manager, fake_devices, server):
    fake_devices(adb=[{"serial": "SAMSUNG0001", "state": "device", "profile": "samsung_old"}])
    result = manager.compatibility(None)
    assert not result.compatible and result.release is None
    assert not any("-stable" in r for r in server.requests)  # nothing requested for unsupported devices


@POSIX_ONLY
def test_compatibility_fastboot(manager, fake_devices):
    fake_devices(
        fastboot=[{"serial": "HUSKYSERIAL01", "state": "fastboot", "profile": "pixel8pro_stock", "unlock_ability": 0}]
    )
    result = manager.compatibility(None)
    assert result.transport == "fastboot" and result.model == "Pixel 8 Pro"
    assert not result.compatible and by_id(result.checks)["unlock"].status == "fail"


@POSIX_ONLY
def test_compatibility_server_down(manager, fake_devices, server):
    server.down = True
    fake_devices(adb=[{"serial": "HUSKYSERIAL01", "state": "device", "profile": "pixel8pro_unlocked"}])
    result = manager.compatibility(None)
    assert result.compatible and result.release is None
    assert by_id(result.checks)["release"].status == "warn"


@POSIX_ONLY
def test_compatibility_old_fastboot_blocks_preparation(manager, fake_devices, monkeypatch):
    monkeypatch.setenv("LMS_FAKE_SCENARIO", "old_fastboot")
    monkeypatch.setattr(compatibility, "MIN_FREE_DISK_BYTES", 1)
    checks = by_id(
        compatibility.host_checks(manager.settings, inspect_tool(manager.devices.runner, Tool.FASTBOOT).to_dict())
    )
    assert checks["fastboot"].status == "fail" and "35.0.1" in checks["fastboot"].detail


def test_disk_space_check(settings, monkeypatch):
    from collections import namedtuple

    usage = namedtuple("usage", "total used free")
    monkeypatch.setattr(compatibility.shutil, "disk_usage", lambda _p: usage(1, 1, 10 * 1024**3))
    checks = by_id(compatibility.host_checks(settings, {"found": True, "version": "35.0.2", "meets_minimum": True}))
    assert checks["disk"].status == "fail" and "32 Go" in checks["disk"].action


def test_catalog_fills_devices_missing_from_overview(manager):
    catalog = manager.catalog()
    rows = {d["codename"]: d for d in catalog["devices"]}
    assert rows["husky"]["stable"] == VERSION
    assert rows["tegu"]["stable"] == VERSION  # absent from overview.json, found via tegu-stable
    assert rows["felix"]["stable"] is None  # not published by the fake server
    assert len(rows) == 21 and catalog["error"] is None


def test_catalog_server_down(manager, server):
    server.down = True
    catalog = manager.catalog()
    assert catalog["error"]["code"] == "release_server_unreachable"
    assert all(d["stable"] is None for d in catalog["devices"])
