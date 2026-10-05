import dataclasses
import json
import os

import pytest

from app.core import platform_tools
from app.core.audit_logger import AuditLogger
from app.core.device_manager import DeviceManager
from app.core.errors import DeviceNotReadyError, ReportNotFoundError, ScanInProgressError
from app.core.platform_tools import CommandRunner
from app.core.security_scanner import SecurityScanner
from tests.conftest import POSIX_ONLY

pytestmark = POSIX_ONLY


def device(profile, **extra):
    return {"serial": "HUSKYSERIAL01", "state": "device", "profile": profile, **extra}


@pytest.fixture
def scanner(settings):
    settings.ensure_directories()
    audit = AuditLogger(settings.audit_log_path)
    return SecurityScanner(settings, DeviceManager(CommandRunner(settings), audit), audit)


def run(scanner):
    scanner.start_scan(None)
    scanner.wait(60)
    return scanner.status()


def test_full_scan_suspicious_device(scanner, fake_devices):
    fake_devices(adb=[device("pixel8pro_stock")])
    status = run(scanner)
    assert status["state"] == "completed" and status["progress"] == 100
    report = scanner.report()
    ids = {f.id for f in report.findings}
    assert {
        "permissions.accessibility",
        "apps.sideloaded",
        "network.proxy",
        "network.weak_wifi",
        "permissions.sms",
        "updates.patch_age",
        "system.usb_debugging",
    } <= ids
    assert report.score < 40 and report.grade == "critical"
    flashlight = report.applications.apps[0]
    assert flashlight.package == "com.example.flashlight" and flashlight.risk_level == "high"
    assert "accessibility" in flashlight.special_access
    for f in report.findings:
        assert f.title and f.why and f.evidence and f.recommendation and f.remediation


def test_clean_grapheneos_device(scanner, fake_devices):
    fake_devices(adb=[device("grapheneos")])
    run(scanner)
    report = scanner.report()
    assert report.score >= 90 and report.grade == "excellent"
    assert report.boot.verified_boot_state == "yellow"
    assert report.network.wifi_security == "WPA3-Personnel (SAE)"


def test_compromised_device(scanner, fake_devices):
    fake_devices(adb=[device("samsung_rooted")])
    run(scanner)
    report = scanner.report()
    ids = {f.id for f in report.findings}
    assert {
        "boot.selinux",
        "encryption.none",
        "boot.root",
        "boot.unlocked",
        "network.adb_wifi",
        "permissions.device_owner",
        "updates.unsupported_android",
    } <= ids
    assert report.score <= 39 and report.severity_counts["critical"] == 2


def test_report_saved_without_identifiers(scanner, fake_devices, settings):
    fake_devices(adb=[device("pixel8pro_stock")])
    run(scanner)
    files = list(settings.reports_dir.glob("security-*.json"))
    assert len(files) == 1
    if os.name != "nt":
        assert files[0].stat().st_mode & 0o777 == 0o600
    raw = files[0].read_text()
    for secret in (
        "HUSKYSERIAL01",
        "abcdef0123456789",
        "AA:BB:CC:DD:EE:FF",
        "Pixel de Jean",
        "Maison-5G",
        "12:34:56:78:9a:bc",
    ):
        assert secret not in raw
    data = json.loads(raw)
    assert "device_id" not in data and data["serial_masked"].startswith("HU")


def test_audit_events(scanner, fake_devices):
    fake_devices(adb=[device("grapheneos")])
    run(scanner)
    events = [e["event"] for e in scanner.audit.read()]
    assert "security_scan_started" in events and "security_scan_completed" in events


def test_missing_optional_command_becomes_limitation(scanner, fake_devices):
    fake_devices(adb=[device("grapheneos", no_cmd_wifi=True)])
    run(scanner)
    report = scanner.report()
    assert any("cmd wifi" in item for item in report.limitations)
    assert report.network.wifi_security is None


def test_disconnect_during_scan_fails_cleanly(scanner, fake_devices):
    fake_devices(adb=[device("pixel8pro_stock", disconnect_after=6)])
    status = run(scanner)
    assert status["state"] == "failed"
    assert status["error"]["code"] == "device_not_found"
    assert "déconnecté pendant l'analyse" in status["error"]["message"]
    with pytest.raises(ReportNotFoundError):
        scanner.report()
    assert "security_scan_failed" in [e["event"] for e in scanner.audit.read()]


def test_fastboot_device_refused(scanner, fake_devices):
    fake_devices(fastboot=[{"serial": "HUSKYSERIAL01", "state": "fastboot"}])
    with pytest.raises(DeviceNotReadyError) as exc:
        scanner.start_scan(None)
    assert "Fastboot" in exc.value.cause


def test_concurrent_scan_refused(scanner, fake_devices, monkeypatch):
    fake_devices(adb=[device("pixel8pro_stock")], hang_on=["dumpsys"])
    for name in ("adb.dumpsys_packages", "adb.dumpsys_device_policy", "adb.dumpsys_connectivity"):
        spec = platform_tools.COMMAND_WHITELIST[name]
        monkeypatch.setitem(platform_tools.COMMAND_WHITELIST, name, dataclasses.replace(spec, timeout=1))
    scanner.start_scan(None)
    with pytest.raises(ScanInProgressError):
        scanner.start_scan(None)
    assert scanner.status()["state"] == "running"
    scanner.wait(30)
    # Timed-out sources become limitations, the scan still completes.
    assert scanner.status()["state"] == "completed"
    assert any("délai dépassé" in item for item in scanner.report().limitations)


def test_report_lookup(scanner, fake_devices):
    with pytest.raises(ReportNotFoundError):
        scanner.report()
    fake_devices(adb=[device("grapheneos")])
    run(scanner)
    report = scanner.report()
    assert scanner.report(device_id=report.device_id).report_id == report.report_id
    assert scanner.report(report_id=report.report_id) is report
    with pytest.raises(ReportNotFoundError):
        scanner.report(report_id="000000000000")


def test_sections_on_demand(scanner, fake_devices):
    fake_devices(adb=[device("pixel8pro_stock")])
    apps, perms, findings = scanner.applications_section(None)
    assert apps.sideloaded == 1 and perms.special_access["accessibility"] == ["com.example.flashlight"]
    net, net_findings, _ = scanner.network_section(None)
    assert net.proxy == "10.0.0.5:8080" and any(f.id == "network.proxy" for f in net_findings)
    upd, _ = scanner.updates_section(None)
    assert upd.security_patch == "2025-09-05"
    boot, _, _ = scanner.boot_section(None)
    assert boot.selinux == "Enforcing" and boot.bootloader_locked is True
    enc, enc_findings = scanner.encryption_section(None)
    assert enc.type == "file" and enc_findings == []
