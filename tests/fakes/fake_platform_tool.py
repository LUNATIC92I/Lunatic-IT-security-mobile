"""Fake adb/fastboot used by the test-suite.

The fixtures in ``tests/conftest.py`` install small executable wrappers named
``adb`` and ``fastboot`` that call :func:`main`, so the real subprocess path of
``CommandRunner`` is exercised without a phone.

Behaviour:

* ``LMS_FAKE_SCENARIO``: ``normal`` (default), ``old_fastboot``, ``hang``,
  ``fail``, ``garbage``;
* ``LMS_FAKE_DEVICES``: path to a JSON file describing connected devices::

      {"adb": [{"serial": "X", "state": "device", "profile": "pixel8pro_stock"}],
       "fastboot": [{"serial": "Y", "state": "fastboot", "profile": "pixel8pro_stock"}],
       "hang_on": ["getprop"]}

* ``LMS_FAKE_CALL_LOG``: every invocation is appended there as JSON.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from tests.fakes.profiles import (  # noqa: E402
    BATTERY_OUTPUT,
    CONNECTIVITY,
    DF_OUTPUT,
    FASTBOOT_GETVAR,
    SCAN_DATA,
    device_policy,
    dumpsys_packages,
    getprop_output,
    wifi_status,
)


def _record_call(tool: str, args: list[str]) -> None:
    log_path = os.environ.get("LMS_FAKE_CALL_LOG")
    if log_path:
        with Path(log_path).open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"tool": tool, "args": args}) + "\n")


def _devices() -> dict:
    path = os.environ.get("LMS_FAKE_DEVICES")
    if not path or not Path(path).exists():
        return {"adb": [], "fastboot": []}
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _find(devices: list[dict], serial: str) -> dict | None:
    return next((d for d in devices if d["serial"] == serial), None)


def _adb_device_command(config: dict, serial: str, args: list[str]) -> int:
    device = _find(config.get("adb", []), serial)
    if device is None:
        sys.stderr.write(f"adb: device '{serial}' not found\n")
        return 1
    if device["state"] != "device":
        sys.stderr.write(f"adb: device {device['state']}\n")
        return 1
    if any(word in config.get("hang_on", []) for word in args):
        time.sleep(30)
    profile = device.get("profile", "pixel8pro_stock")
    scan = SCAN_DATA.get(profile, SCAN_DATA["pixel8pro_stock"])
    if device.get("disconnect_after"):
        # Simulate a cable unplugged mid-scan: the device vanishes after N commands.
        counter = Path(os.environ["LMS_FAKE_DEVICES"]).with_suffix(".count")
        count = int(counter.read_text()) + 1 if counter.exists() else 1
        counter.write_text(str(count))
        if count > device["disconnect_after"]:
            sys.stderr.write(f"adb: device '{serial}' not found\n")
            return 1
    if args == ["get-state"]:
        sys.stdout.write("device\n")
    elif args == ["shell", "getprop"]:
        sys.stdout.write(getprop_output(profile))
    elif args[:3] == ["shell", "settings", "get"] and len(args) == 5:
        values = device.get("settings", {"global/adb_enabled": "1", "global/development_settings_enabled": "1"})
        sys.stdout.write(values.get(f"{args[3]}/{args[4]}", "null") + "\n")
    elif args == ["shell", "df", "-k", "/data"]:
        if device.get("df") == "denied":
            sys.stdout.write("df: /data: Permission denied\n")
            return 1
        sys.stdout.write(DF_OUTPUT)
    elif args == ["shell", "dumpsys", "battery"]:
        sys.stdout.write(BATTERY_OUTPUT)
    elif args[:3] == ["shell", "settings", "list"] and len(args) == 4:
        values = scan.get(args[3], {})
        sys.stdout.write("".join(f"{k}={v}\n" for k, v in values.items()))
    elif args == ["shell", "pm", "list", "packages", "-3"]:
        sys.stdout.write("".join(f"package:{a['name']}\n" for a in scan.get("apps", []) if not a["system"]))
    elif args == ["shell", "pm", "list", "packages", "-d"]:
        sys.stdout.write("")
    elif args == ["shell", "dumpsys", "package", "packages"]:
        sys.stdout.write(dumpsys_packages(scan.get("apps", [])))
    elif args == ["shell", "dumpsys", "device_policy"]:
        sys.stdout.write(device_policy(scan.get("admins", []), scan.get("owner")))
    elif args == ["shell", "appops", "query-op", "REQUEST_INSTALL_PACKAGES", "allow"]:
        allowed = scan.get("install_allowed", [])
        sys.stdout.write("".join(f"{p}\n" for p in allowed) if allowed else "No operations.\n")
    elif args == ["shell", "cmd", "wifi", "status"]:
        if device.get("no_cmd_wifi"):
            sys.stdout.write("cmd: Can't find service: wifi\n")
            return 20
        sys.stdout.write(wifi_status(scan.get("wifi_security")))
    elif args == ["shell", "dumpsys", "connectivity"]:
        sys.stdout.write(CONNECTIVITY)
    elif args == ["shell", "getenforce"]:
        sys.stdout.write(scan.get("selinux", "Enforcing") + "\n")
    elif args == ["shell", "which", "su"]:
        if scan.get("su"):
            sys.stdout.write(scan["su"] + "\n")
            return 0
        return 1
    else:
        sys.stderr.write(f"adb: unsupported fake command {args}\n")
        return 1
    return 0


def _adb(args: list[str], scenario: str) -> int:
    config = _devices()
    if args == ["version"]:
        sys.stdout.write("Android Debug Bridge version 1.0.41\nVersion 35.0.2-12147458\nInstalled as /fake/adb\n")
        return 0
    if args == ["devices", "-l"]:
        lines = ["List of devices attached"]
        for device in config.get("adb", []):
            if device["state"] == "no permissions":
                lines.append(
                    f"{device['serial']}       no permissions (missing udev rules? user is in the plugdev group); "
                    "see [http://developer.android.com/tools/device.html] usb:1-2 transport_id:9"
                )
                continue
            extra = device.get("attrs", "usb:1-1 product:husky model:Pixel_8_Pro device:husky transport_id:1")
            lines.append(f"{device['serial']}\t{device['state']} {extra}".rstrip())
        sys.stdout.write("\n".join(lines) + "\n\n")
        return 0
    if args in (["start-server"], ["kill-server"]):
        return 0
    if len(args) >= 3 and args[0] == "-s":
        return _adb_device_command(config, args[1], args[2:])
    sys.stderr.write(f"adb: unknown command {' '.join(args)}\n")
    return 1


def _fastboot(args: list[str], scenario: str) -> int:
    config = _devices()
    if args == ["--version"]:
        version = "34.0.5-10900879" if scenario == "old_fastboot" else "35.0.2-12147458"
        sys.stdout.write(f"fastboot version {version}\nInstalled as /fake/fastboot\n")
        return 0
    if args == ["devices"]:
        for device in config.get("fastboot", []):
            sys.stdout.write(f"{device['serial']}\t{device['state']}\n")
        return 0
    if len(args) == 4 and args[0] == "-s" and args[2:] == ["getvar", "all"]:
        device = _find(config.get("fastboot", []), args[1])
        if device is None:
            sys.stderr.write("< waiting for any device >\n")
            time.sleep(30)
            return 1
        sys.stderr.write(FASTBOOT_GETVAR[device.get("profile", "pixel8pro_stock")])
        return 0
    sys.stderr.write(f"fastboot: unknown command {' '.join(args)}\n")
    return 1


def main(tool: str, args: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if args is None else args)
    _record_call(tool, args)
    scenario = os.environ.get("LMS_FAKE_SCENARIO", "normal")
    if scenario == "hang":
        time.sleep(30)
        return 0
    if scenario == "fail":
        sys.stderr.write("error: fake failure\n")
        return 1
    if scenario == "garbage":
        sys.stdout.write("something unexpected\n")
        return 0
    return _adb(args, scenario) if tool == "adb" else _fastboot(args, scenario)
