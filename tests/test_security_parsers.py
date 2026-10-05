from datetime import datetime

from app.security import applications, network, permissions
from app.security.android_audit import parse_settings_list
from tests.fakes.profiles import CONNECTIVITY, SCAN_DATA, device_policy, dumpsys_packages, wifi_status

P = "android.permission."


def test_dumpsys_packages_parsing():
    packages = applications.parse_dumpsys_packages(dumpsys_packages(SCAN_DATA["pixel8pro_stock"]["apps"]))
    assert "com.android.hidden" not in packages  # "Hidden system packages" section ignored
    flashlight = packages["com.example.flashlight"]
    assert flashlight.installer == "com.google.android.packageinstaller"
    assert flashlight.version_name == "3.1" and flashlight.target_sdk == 34
    assert P + "READ_SMS" in flashlight.runtime_granted
    assert P + "POST_NOTIFICATIONS" not in flashlight.runtime_granted  # granted=false
    assert P + "INTERNET" in flashlight.install_granted
    assert "SYSTEM" not in flashlight.flags
    settings = packages["com.android.settings"]
    assert settings.installer is None and settings.is_system_flag
    # User 10 grants READ_SMS to everyone in the fixture: must not leak into user 0.
    assert P + "READ_SMS" not in packages["com.whatsapp"].runtime_granted
    assert packages["com.android.uninstalled"].installed_for_user0 is False


def test_package_list_and_installers():
    assert applications.parse_package_list("package:com.a\npackage:com.b\n\nnoise\npackage:\n") == {"com.a", "com.b"}
    assert applications.installer_label("com.android.vending", False) == "Google Play Store"
    assert applications.is_sideloaded("com.google.android.packageinstaller", False)
    assert applications.is_sideloaded(None, False)
    assert not applications.is_sideloaded(None, True)
    assert not applications.is_sideloaded("app.grapheneos.apps", False)


def test_build_app_infos_recent_and_skip_uninstalled():
    data = SCAN_DATA["pixel8pro_stock"]
    packages = applications.parse_dumpsys_packages(dumpsys_packages(data["apps"]))
    apps = applications.build_app_infos(
        packages, {"com.whatsapp", "com.example.flashlight", "org.mozilla.firefox"}, set(), datetime.now()
    )
    names = {a.package for a in apps}
    assert "com.android.uninstalled" not in names
    by_name = {a.package: a for a in apps}
    assert by_name["com.example.flashlight"].recently_installed and by_name["com.example.flashlight"].sideloaded
    assert not by_name["com.whatsapp"].recently_installed
    assert by_name["com.android.chrome"].system


def test_device_policy_formats():
    admins, owner = permissions.parse_device_policy(
        device_policy(
            ["com.google.android.gms/.mdm.receivers.MdmDeviceAdminReceiver", "com.example.app/com.example.app.Admin"],
            "com.corp.mdm",
        )
    )
    assert admins == ["com.google.android.gms", "com.example.app"] and owner == "com.corp.mdm"
    legacy = (
        "  Enabled Device Admins (User 0, provisioningState: 0):\n"
        "    ComponentInfo{com.legacy.admin/com.legacy.admin.Receiver}:\n"
        "      uid=10001\n"
        "  mPasswordOwner=-1\n"
    )
    assert permissions.parse_device_policy(legacy) == (["com.legacy.admin"], None)
    assert permissions.parse_device_policy("") == ([], None)


def test_component_and_appops_parsing():
    assert permissions.parse_component_list("a.b/.S:c.d/c.d.X:a.b/.T") == ["a.b", "c.d"]
    assert permissions.parse_component_list("null") == [] and permissions.parse_component_list(None) == []
    assert permissions.parse_appops_query("No operations.\n") == []
    assert permissions.parse_appops_query("org.mozilla.firefox\ncom.x.y\n") == ["org.mozilla.firefox", "com.x.y"]


def test_settings_list_keeps_allowlist_only():
    output = "adb_enabled=1\ndevice_name=Pixel de Jean\nhttp_proxy=1.2.3.4:80\nmalformed\n"
    assert parse_settings_list(output, "global") == {"adb_enabled": "1", "http_proxy": "1.2.3.4:80"}
    secure = parse_settings_list("android_id=abc\nbluetooth_address=AA\nsms_default_application=x.y\n", "secure")
    assert secure == {"sms_default_application": "x.y"}


def test_wifi_status_parsing_drops_identifiers():
    status = network.parse_wifi_status(wifi_status(4))
    assert status.enabled and status.connected and status.security_type == 4
    assert not hasattr(status, "ssid")
    disabled = network.parse_wifi_status(wifi_status(None))
    assert disabled.enabled is False and disabled.connected is False
    assert network.parse_wifi_status("Wifi is enabled\nWifi is not connected\n").connected is False


def test_connectivity_parsing():
    status = network.parse_connectivity(CONNECTIVITY)
    assert status.transports == ["WIFI", "CELLULAR"]
    assert status.validated is True
    assert status.dns_servers == ["192.168.1.1", "fe80::1"]  # default network only
    assert network.parse_connectivity("").transports == []


def test_network_section_proxy_variants():
    section = network.build_network_section({"http_proxy": ":0"}, {}, None, None)
    assert section.proxy is None
    section = network.build_network_section(
        {"global_http_proxy_host": "proxy.corp", "global_http_proxy_port": "3128"}, {}, None, None
    )
    assert section.proxy == "proxy.corp:3128"
