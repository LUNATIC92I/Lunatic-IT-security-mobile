import pytest

from app.models.security_report import AppInfo, Category, Finding, Severity
from app.security import permissions, recommendations, updates


def finding(severity, category=Category.SYSTEM, fid="x"):
    return Finding(
        id=fid,
        category=category,
        severity=severity,
        title="t",
        why="w",
        evidence="e",
        recommendation="r",
        remediation="m",
    )


def test_perfect_score():
    score, categories = recommendations.compute_score([])
    assert score == 100 and all(c.score == 100 for c in categories)
    assert recommendations.grade_for(score) == ("excellent", "Excellent")


@pytest.mark.parametrize(
    ("score", "grade"),
    [
        (100, "excellent"),
        (90, "excellent"),
        (89, "good"),
        (75, "good"),
        (74, "average"),
        (60, "average"),
        (59, "weak"),
        (40, "weak"),
        (39, "critical"),
        (0, "critical"),
    ],
)
def test_grade_thresholds(score, grade):
    assert recommendations.grade_for(score)[0] == grade


def test_category_cap_limits_many_small_findings():
    many = [finding(Severity.MEDIUM, Category.APPLICATIONS, f"a{i}") for i in range(20)]
    score, categories = recommendations.compute_score(many)
    apps = next(c for c in categories if c.category is Category.APPLICATIONS)
    assert apps.penalty == recommendations.CATEGORY_CAPS[Category.APPLICATIONS] and apps.score == 0
    assert score == 85


def test_critical_caps_score():
    score, _ = recommendations.compute_score([finding(Severity.CRITICAL, Category.ENCRYPTION)])
    assert score <= 39
    score, _ = recommendations.compute_score([finding(Severity.HIGH, Category.BOOT)])
    assert score <= 74


def test_info_findings_do_not_penalize():
    assert recommendations.compute_score([finding(Severity.INFO)])[0] == 100


def test_sorting_and_counts():
    items = [finding(Severity.LOW, fid="l"), finding(Severity.CRITICAL, fid="c"), finding(Severity.MEDIUM, fid="m")]
    assert [f.id for f in recommendations.sort_findings(items)] == ["c", "m", "l"]
    assert recommendations.severity_counts(items) == {"critical": 1, "high": 0, "medium": 1, "low": 1, "info": 0}


def app(name, groups=(), system=False, sideloaded=False, special=()):
    perms = [p for g in groups for p in sorted(permissions.PERMISSION_GROUPS[g][1])[:1]]
    return AppInfo(
        package=name,
        system=system,
        installer_label="x",
        sideloaded=sideloaded,
        granted_permissions=perms,
        special_access=list(special),
    )


def test_contextual_scoring():
    sms_default = app("com.sms", ["sms", "contacts"])
    other_sms = app("com.other", ["sms", "contacts"])
    for a in (sms_default, other_sms):
        a.granted_groups = permissions.granted_groups(a.granted_permissions)
        permissions.score_app(a, "com.sms")
    assert sms_default.risk_score < other_sms.risk_score
    system = app("com.android.x", ["camera", "microphone", "sms"], system=True)
    system.granted_groups = permissions.granted_groups(system.granted_permissions)
    permissions.score_app(system, None)
    assert system.risk_score == 0


def test_permission_is_not_malicious_by_itself():
    messenger = app("com.messenger", ["camera", "microphone"])
    messenger.granted_groups = permissions.granted_groups(messenger.granted_permissions)
    permissions.score_app(messenger, None)
    assert messenger.risk_level == "low"
    spy = app("com.spy", ["camera", "microphone", "location", "sms"], sideloaded=True, special=["accessibility"])
    spy.granted_groups = permissions.granted_groups(spy.granted_permissions)
    permissions.score_app(spy, None)
    assert spy.risk_level == "high" and any("Accès spécial" in r for r in spy.risk_reasons)


def test_default_sms_app_not_flagged():
    apps = [app("com.sms", ["sms"])]
    _section, findings = permissions.analyze_permissions(
        apps,
        accessibility=[],
        notification_listeners=[],
        device_admins=[],
        device_owner=None,
        install_allowed=[],
        always_on_vpn=None,
        default_sms="com.sms",
    )
    assert not any(f.id == "permissions.sms" for f in findings)


def test_system_accessibility_service_not_flagged():
    apps = [app("com.google.android.marvin.talkback", system=True)]
    _section, findings = permissions.analyze_permissions(
        apps,
        accessibility=["com.google.android.marvin.talkback"],
        notification_listeners=[],
        device_admins=[],
        device_owner=None,
        install_allowed=[],
        always_on_vpn=None,
        default_sms=None,
    )
    assert findings == []


@pytest.mark.parametrize(
    ("patch", "expected"),
    [
        ("2026-09-20", None),
        ("2026-08-01", Severity.LOW),
        ("2026-05-01", Severity.MEDIUM),
        ("2025-01-01", Severity.HIGH),
    ],
)
def test_patch_age_severity(patch, expected):
    from datetime import date

    section = updates.build_updates_section(
        {"ro.build.version.security_patch": patch, "ro.build.version.sdk": "36"}, today=date(2026, 10, 5)
    )
    found = [f for f in updates.analyze_updates(section) if f.id == "updates.patch_age"]
    assert (found[0].severity if found else None) == expected
