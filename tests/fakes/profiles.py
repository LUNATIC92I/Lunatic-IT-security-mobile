"""Realistic device outputs for the fake adb/fastboot.

Values follow real Pixel/Samsung outputs (property names, df and dumpsys
formats, fastboot ``getvar all`` layout). Serial properties are included on
purpose to check that the application discards them.
"""

from __future__ import annotations

_COMMON = {
    "ro.build.version.sdk": "35",
    "ro.build.version.release": "15",
    "ro.build.version.release_or_codename": "15",
    "ro.build.type": "user",
    "ro.build.tags": "release-keys",
    "ro.crypto.state": "encrypted",
    "ro.crypto.type": "file",
    "ro.oem_unlock_supported": "1",
    "persist.sys.timezone": "Europe/Paris",
    "ro.boot.slot_suffix": "_a",
}

PROFILES: dict[str, dict[str, str]] = {
    "pixel8pro_stock": {
        **_COMMON,
        "ro.product.manufacturer": "Google",
        "ro.product.brand": "google",
        "ro.product.model": "Pixel 8 Pro",
        "ro.product.device": "husky",
        "ro.product.name": "husky",
        "ro.build.id": "AP4A.250905.002",
        "ro.build.display.id": "AP4A.250905.002",
        "ro.build.version.security_patch": "2025-09-05",
        "ro.boot.verifiedbootstate": "green",
        "ro.boot.flash.locked": "1",
        "ro.boot.vbmeta.device_state": "locked",
        "sys.oem_unlock_allowed": "0",
        "ro.bootloader": "ripcurrent-15.2-12345678",
        "gsm.version.baseband": "g5300i-250701-250801-B-13888888",
        "ro.serialno": "HUSKYSERIAL01",
        "ro.boot.serialno": "HUSKYSERIAL01",
    },
    "pixel8pro_unlocked": {
        **_COMMON,
        "ro.product.manufacturer": "Google",
        "ro.product.brand": "google",
        "ro.product.model": "Pixel 8 Pro",
        "ro.product.device": "husky",
        "ro.build.id": "AP4A.250905.002",
        "ro.build.version.security_patch": "2025-09-05",
        "ro.boot.verifiedbootstate": "orange",
        "ro.boot.flash.locked": "0",
        "ro.boot.vbmeta.device_state": "unlocked",
        "sys.oem_unlock_allowed": "1",
    },
    "samsung_old": {
        **_COMMON,
        "ro.build.version.sdk": "30",
        "ro.build.version.release": "11",
        "ro.build.version.release_or_codename": "11",
        "ro.product.manufacturer": "samsung",
        "ro.product.brand": "samsung",
        "ro.product.model": "SM-A515F",
        "ro.product.device": "a51",
        "ro.build.id": "RP1A.200720.012",
        "ro.build.version.security_patch": "2022-03-01",
        "ro.boot.verifiedbootstate": "green",
        "ro.boot.flash.locked": "1",
    },
    "minimal": {
        "ro.product.manufacturer": "Generic",
        "ro.product.model": "Board",
        "ro.build.version.release": "9",
        "ro.build.version.sdk": "28",
    },
}

DF_OUTPUT = (
    "Filesystem       1K-blocks     Used Available Use% Mounted on\n"
    "/dev/block/dm-48 236107512 41210988 194765452  18% /data\n"
)

BATTERY_OUTPUT = """Current Battery Service state:
  AC powered: false
  USB powered: true
  Wireless powered: false
  Max charging current: 500000
  status: 2
  health: 2
  present: true
  level: 78
  scale: 100
  voltage: 4123
  temperature: 286
  technology: Li-ion
"""

FASTBOOT_GETVAR = {
    "pixel8pro_stock": """(bootloader) cpu-abi:arm64-v8a
(bootloader) product:husky
(bootloader) serialno:HUSKYSERIAL01
(bootloader) partition-size:boot_a: 0x4000000
(bootloader) unlocked:no
(bootloader) secure:yes
(bootloader) version-bootloader:ripcurrent-15.2-12345678
(bootloader) version-baseband:g5300i-250701-250801-B-13888888
(bootloader) current-slot:a
(bootloader) is-userspace:no
(bootloader) battery-soc-ok:yes
all: Done!
Finished. Total time: 0.212s
""",
    "pixel8pro_unlocked": """(bootloader) product:husky
(bootloader) unlocked:yes
(bootloader) secure:yes
(bootloader) current-slot:b
all: Done!
""",
}


def getprop_output(profile: str, overrides: dict[str, str] | None = None) -> str:
    props = {**PROFILES[profile], **(overrides or {})}
    return "".join(f"[{key}]: [{value}]\n" for key, value in sorted(props.items()))


# --------------------------------------------------------------------------
# Security audit outputs (phase 3)
# --------------------------------------------------------------------------
def _recent_patch(days: int = 10) -> str:
    """A security patch a few days old, relative to today, so the fake never "ages"."""
    from datetime import date, timedelta

    return (date.today() - timedelta(days=days)).isoformat()


PROFILES["grapheneos"] = {
    **PROFILES["pixel8pro_stock"],
    "ro.build.version.security_patch": _recent_patch(),
    "ro.vendor.build.security_patch": _recent_patch(),
    "ro.boot.verifiedbootstate": "yellow",
    "ro.build.version.release": "16",
    "ro.build.version.release_or_codename": "16",
    "ro.build.version.sdk": "36",
    # GrapheneOS uses its release version as the build number.
    "ro.build.version.incremental": "2026100200",
}
PROFILES["samsung_rooted"] = {
    **PROFILES["samsung_old"],
    "ro.boot.verifiedbootstate": "orange",
    "ro.boot.flash.locked": "0",
    "ro.build.tags": "test-keys",
    "ro.crypto.state": "unencrypted",
}


def _app(
    name,
    installer="com.android.vending",
    system=False,
    runtime=(),
    install=(),
    first="2024-02-10 09:00:00",
    version="1.0",
    user0_installed=True,
):
    return {
        "name": name,
        "installer": installer,
        "system": system,
        "runtime": list(runtime),
        "install": list(install),
        "first": first,
        "version": version,
        "installed": user0_installed,
    }


def recent_date(days: int = 3) -> str:
    from datetime import datetime, timedelta

    return (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")


P = "android.permission."
STANDARD_APPS = [
    _app("com.android.settings", installer=None, system=True, install=[P + "INTERNET", P + "WRITE_SECURE_SETTINGS"]),
    _app(
        "com.google.android.apps.messaging",
        installer=None,
        system=True,
        runtime=[P + "READ_SMS", P + "SEND_SMS", P + "RECEIVE_SMS", P + "READ_CONTACTS"],
    ),
    _app("com.google.android.gms", installer=None, system=True, runtime=[P + "ACCESS_FINE_LOCATION", P + "CAMERA"]),
    _app("com.android.chrome", installer="com.android.vending", system=True, runtime=[P + "CAMERA"]),
    _app("com.android.uninstalled", installer=None, system=True, user0_installed=False),
    _app(
        "com.whatsapp",
        runtime=[P + "CAMERA", P + "RECORD_AUDIO", P + "READ_CONTACTS"],
        install=[P + "INTERNET"],
        version="2.26.18.7",
    ),
    _app("org.mozilla.firefox", runtime=[P + "CAMERA"], install=[P + "INTERNET", P + "REQUEST_INSTALL_PACKAGES"]),
]
SUSPICIOUS_APP = _app(
    "com.example.flashlight",
    installer="com.google.android.packageinstaller",
    runtime=[
        P + "CAMERA",
        P + "RECORD_AUDIO",
        P + "ACCESS_FINE_LOCATION",
        P + "ACCESS_BACKGROUND_LOCATION",
        P + "READ_SMS",
        P + "RECEIVE_SMS",
        P + "READ_CONTACTS",
        P + "READ_CALL_LOG",
    ],
    install=[P + "INTERNET", P + "RECEIVE_BOOT_COMPLETED"],
    first="RECENT",
    version="3.1",
)

SCAN_DATA = {
    "pixel8pro_stock": {
        "apps": STANDARD_APPS + [SUSPICIOUS_APP],
        "global": {
            "adb_enabled": "1",
            "development_settings_enabled": "1",
            "private_dns_mode": "off",
            "http_proxy": "10.0.0.5:8080",
            "bluetooth_on": "1",
            "airplane_mode_on": "0",
            "device_name": "Pixel de Jean",
            "verifier_verify_adb_installs": "1",
        },
        "secure": {
            "enabled_accessibility_services": "com.example.flashlight/com.example.flashlight.Svc",
            "accessibility_enabled": "1",
            "enabled_notification_listeners": "com.example.flashlight/.Listener:com.google.android.gms/.Listener",
            "sms_default_application": "com.google.android.apps.messaging",
            "android_id": "abcdef0123456789",
            "bluetooth_address": "AA:BB:CC:DD:EE:FF",
        },
        "admins": [
            "com.google.android.gms/.mdm.receivers.MdmDeviceAdminReceiver",
            "com.example.flashlight/.AdminReceiver",
        ],
        "owner": None,
        "install_allowed": ["org.mozilla.firefox", "com.example.flashlight"],
        "wifi_security": 0,
        "selinux": "Enforcing",
        "su": None,
    },
    "grapheneos": {
        "apps": STANDARD_APPS[:4]
        + [_app("com.whatsapp", installer="app.grapheneos.apps", runtime=[P + "CAMERA", P + "RECORD_AUDIO"])],
        "global": {
            "adb_enabled": "1",
            "development_settings_enabled": "1",
            "private_dns_mode": "hostname",
            "private_dns_specifier": "dns.quad9.net",
            "http_proxy": ":0",
        },
        "secure": {
            "enabled_accessibility_services": "null",
            "sms_default_application": "com.google.android.apps.messaging",
        },
        "admins": [],
        "owner": None,
        "install_allowed": [],
        "wifi_security": 4,
        "selinux": "Enforcing",
        "su": None,
    },
    "samsung_rooted": {
        "apps": STANDARD_APPS,
        "global": {
            "adb_enabled": "1",
            "development_settings_enabled": "1",
            "adb_wifi_enabled": "1",
            "verifier_verify_adb_installs": "0",
        },
        "secure": {"install_non_market_apps": "1"},
        "admins": [],
        "owner": "com.corp.mdm",
        "install_allowed": [],
        "wifi_security": None,
        "selinux": "Permissive",
        "su": "/system/xbin/su",
    },
}


def dumpsys_packages(apps: list[dict]) -> str:
    lines = ["Database versions:", "  Internal:", "    sdkVersion=35", "", "Packages:"]
    for app in apps:
        first = recent_date() if app["first"] == "RECENT" else app["first"]
        flags = "SYSTEM HAS_CODE" if app["system"] else "HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP"
        lines += [
            f"  Package [{app['name']}] (1a2b3c):",
            "    userId=10123",
            f"    pkg=Package{{4d5e6f {app['name']}}}",
            f"    codePath=/data/app/~~x==/{app['name']}-y==",
            "    versionCode=1234 minSdk=26 targetSdk=34",
            f"    versionName={app['version']}",
            f"    flags=[ {flags} ]",
            "    privateFlags=[ PRIVATE_FLAG_ACTIVITIES_RESIZE_MODE_RESIZEABLE ]",
            f"    timeStamp={first}",
            f"    lastUpdateTime={first}",
            f"    installerPackageName={app['installer'] or 'null'}",
            "    packageSource=0",
            f"    pkgFlags=[ {flags} ]",
            "    requested permissions:",
        ]
        lines += [f"      {perm}" for perm in app["runtime"] + app["install"]]
        lines.append("    install permissions:")
        lines += [f"      {perm}: granted=true" for perm in app["install"]]
        installed = "true" if app["installed"] else "false"
        lines += [
            f"    User 0: ceDataInode=4242 installed={installed} hidden=false suspended=false stopped=false "
            "notLaunched=false enabled=0 instant=false virtual=false",
            f"      firstInstallTime={first}",
            "      gids=[3003]",
            "      runtime permissions:",
        ]
        lines += [
            f"        {perm}: granted=true, flags=[ USER_SET|USER_SENSITIVE_WHEN_GRANTED ]" for perm in app["runtime"]
        ]
        lines += [f"        {P}POST_NOTIFICATIONS: granted=false, flags=[ USER_SET ]"]
        lines += [
            "    User 10: ceDataInode=0 installed=true hidden=false suspended=false enabled=0",
            "      runtime permissions:",
            f"        {P}READ_SMS: granted=true, flags=[ ]",
        ]
    lines += [
        "",
        "Hidden system packages:",
        "  Package [com.android.hidden] (777):",
        "    requested permissions:",
        f"      {P}READ_SMS",
    ]
    return "\n".join(lines) + "\n"


def device_policy(admins: list[str], owner: str | None) -> str:
    lines = ["Current Device Policy Manager state:", "  Immutable state:", "    mHasFeature=true"]
    if owner:
        lines += ["  Device Owner: ", f"    admin=ComponentInfo{{{owner}/{owner}.AdminReceiver}}", "    name=Corp MDM"]
    lines += ["", "  Enabled Device Admins (User 0, provisioningState: 3):"]
    for admin in admins:
        lines += [f"    {admin}:", "      uid=10123", "      testOnlyAdmin=false"]
    lines += ["", "  Stats:", "    mAffiliationIds=[]"]
    return "\n".join(lines) + "\n"


def wifi_status(security: int | None) -> str:
    if security is None:
        return "Wifi is disabled\nWifi scanning is only available when wifi is enabled\n"
    return (
        "Wifi is enabled\nWifi scanning is always available\n==== Primary ClientModeManager instance ====\n"
        'Wifi is connected to "Maison-5G"\n'
        'WifiInfo: SSID: "Maison-5G", BSSID: 12:34:56:78:9a:bc, MAC: 02:00:00:00:00:00, IP: /192.168.1.23, '
        f"Security type: {security}, Supplicant state: COMPLETED, Wi-Fi standard: 11ax, RSSI: -52, "
        "Link speed: 866Mbps, Frequency: 5180MHz\n"
    )


CONNECTIVITY = """Current Networks:
  NetworkAgentInfo{network{100}  handle{432902426637}  ni{WIFI CONNECTED extra: } created=2026-10-05T10:00:00Z Score(Policies : IS_VALIDATED&IS_UNMETERED ; KeepConnected : 0)  lp{{InterfaceName: wlan0 LinkAddresses: [ 192.168.1.23/24 ] DnsAddresses: [ /192.168.1.1,/fe80::1 ] Domains: home MTU: 1500}}  nc{[ Transports: WIFI Capabilities: NOT_METERED&INTERNET&NOT_RESTRICTED&TRUSTED&NOT_VPN&VALIDATED&NOT_ROAMING LinkUpBandwidth>=40000Kbps]}}
  NetworkAgentInfo{network{101}  handle{1}  ni{MOBILE[LTE] CONNECTED extra: } lp{{InterfaceName: rmnet0 DnsAddresses: [ /10.10.10.10 ]}}  nc{[ Transports: CELLULAR Capabilities: INTERNET&NOT_RESTRICTED&TRUSTED&NOT_VPN&VALIDATED]}}
Active default network: 100
"""

PROFILES["pixel8pro_oem_unlock"] = {**PROFILES["pixel8pro_stock"], "sys.oem_unlock_allowed": "1"}
SCAN_DATA["pixel8pro_oem_unlock"] = SCAN_DATA["grapheneos"]
