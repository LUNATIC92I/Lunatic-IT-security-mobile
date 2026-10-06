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


def _state_path() -> Path | None:
    path = os.environ.get("LMS_FAKE_DEVICES")
    return Path(path).with_suffix(".state.json") if path else None


def _load_state(serial: str) -> dict:
    path = _state_path()
    data = json.loads(path.read_text(encoding="utf-8")) if path and path.exists() else {}
    return data.get(serial, {"global": {}, "secure": {}, "deleted": [], "install_denied": [], "revoked": {}})


def _save_state(serial: str, state: dict) -> None:
    path = _state_path()
    if path is None:
        return
    data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    data[serial] = state
    path.write_text(json.dumps(data), encoding="utf-8")


def _settings_view(scan: dict, state: dict, namespace: str) -> dict:
    values = dict(scan.get(namespace, {}))
    values.update(state.get(namespace, {}))
    for key in state.get("deleted", []):
        ns, _, name = key.partition("/")
        if ns == namespace:
            values.pop(name, None)
    return values


def _apps_with_state(scan: dict, state: dict) -> list[dict]:
    apps = []
    for app in scan.get("apps", []):
        revoked = set(state.get("revoked", {}).get(app["name"], []))
        apps.append({**app, "runtime": [p for p in app["runtime"] if p not in revoked]})
    return apps


ACCOUNTS_OUTPUT = """User UserInfo{0:Owner:c13}:
  Accounts: 3
    Account {name=jean.dupont@gmail.com, type=com.google}
    Account {name=jean.dupont@gmail.com, type=com.whatsapp}
    Account {name=work@corp.example, type=com.google}

  Active Sessions: 0
"""


def _device_path(device: dict, remote: str) -> Path | None:
    root = device.get("root")
    if not root or not remote.startswith("/") or ".." in remote.split("/"):
        return None
    return Path(root) / remote.lstrip("/")


def _sha256(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


def _storage_command(device: dict, args: list[str]) -> int | None:
    """Shared storage / APK commands used by the backup. Returns None if not handled."""
    if args[:3] == ["shell", "du", "-sk"] and len(args) == 4:
        local = _device_path(device, args[3])
        if local is None or not local.is_dir():
            sys.stderr.write(f"du: {args[3]}: No such file or directory\n")
            return 1
        size = sum(f.stat().st_size for f in local.rglob("*") if f.is_file())
        sys.stdout.write(f"{(size + 1023) // 1024}\t{args[3]}\n")
        return 0
    if args[:2] == ["shell", "find"] and args[3:] == ["-type", "f", "-exec", "sha256sum", "{}", "+"]:
        local = _device_path(device, args[2])
        if local is None or not local.is_dir():
            sys.stderr.write(f"find: {args[2]}: No such file or directory\n")
            return 1
        for file in sorted(f for f in local.rglob("*") if f.is_file()):
            remote = args[2] + "/" + file.relative_to(local).as_posix()
            sys.stdout.write(f"{_sha256(file)}  {remote}\n")
        return 0
    if args[:3] == ["shell", "pm", "path"] and len(args) == 4:
        apks = device.get("apks", {}).get(args[3])
        if not apks:
            return 1
        sys.stdout.write("".join(f"package:{a}\n" for a in apks))
        return 0
    if args[:2] == ["shell", "sha256sum"] and len(args) == 3:
        local = _device_path(device, args[2])
        if local is None or not local.is_file():
            sys.stderr.write(f"sha256sum: {args[2]}: No such file or directory\n")
            return 1
        sys.stdout.write(f"{_sha256(local)}  {args[2]}\n")
        return 0
    if args[:1] == ["pull"] and len(args) == 3:
        import shutil

        if device.get("slow_pull"):
            time.sleep(device["slow_pull"])
        if device.get("fail_pull"):
            sys.stderr.write(f"adb: error: failed to copy '{args[1]}': no response: Connection reset by peer\n")
            return 1
        source = _device_path(device, args[1])
        if source is None or not source.exists():
            sys.stderr.write(f"adb: error: failed to stat remote object '{args[1]}': No such file or directory\n")
            return 1
        destination = Path(args[2])
        target = destination / source.name if destination.is_dir() else destination
        if source.is_dir():
            shutil.copytree(source, target, dirs_exist_ok=True)
        else:
            shutil.copy2(source, target)
        for rel in device.get("corrupt_pull", []):
            victim = destination / rel
            if victim.is_file():
                data = bytearray(victim.read_bytes())
                data[0] ^= 0xFF
                victim.write_bytes(bytes(data))
        for rel in device.get("appear_during_pull", []):
            extra = destination / rel
            extra.parent.mkdir(parents=True, exist_ok=True)
            extra.write_bytes(b"new photo")
        sys.stdout.write(f"{args[1]}: 1 file pulled, 0 skipped.\n")
        return 0
    return None


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
    state = _load_state(serial)
    refuse = device.get("refuse_changes", False)
    if state.get("global", {}).get("adb_enabled") == "0" or state.get("mode", "adb") != "adb":
        sys.stderr.write(f"adb: device '{serial}' not found\n")
        return 1
    if args == ["reboot", "bootloader"]:
        state["mode"] = "fastboot"
        _save_state(serial, state)
        return 0
    handled = _storage_command(device, args)
    if handled is not None:
        return handled
    if args == ["get-state"]:
        sys.stdout.write("device\n")
    elif args == ["shell", "getprop"]:
        sys.stdout.write(getprop_output(profile, device.get("props")))
    elif args[:3] == ["shell", "settings", "get"] and len(args) == 5:
        if "settings" in device:
            values = device["settings"]
            sys.stdout.write(values.get(f"{args[3]}/{args[4]}", "null") + "\n")
        else:
            sys.stdout.write(_settings_view(scan, state, args[3]).get(args[4], "null") + "\n")
    elif args[:3] == ["shell", "settings", "put"] and len(args) == 6:
        if refuse:
            sys.stdout.write("java.lang.SecurityException: Permission denial: writing to settings requires\n")
            return 0
        state.setdefault(args[3], {})[args[4]] = args[5]
        if f"{args[3]}/{args[4]}" in state.get("deleted", []):
            state["deleted"].remove(f"{args[3]}/{args[4]}")
        _save_state(serial, state)
    elif args[:3] == ["shell", "settings", "delete"] and len(args) == 5:
        state.setdefault("deleted", []).append(f"{args[3]}/{args[4]}")
        state.get(args[3], {}).pop(args[4], None)
        _save_state(serial, state)
    elif args[:3] == ["shell", "appops", "set"] and args[4:] == ["REQUEST_INSTALL_PACKAGES", "deny"]:
        state.setdefault("install_denied", []).append(args[3])
        _save_state(serial, state)
    elif args[:3] == ["shell", "pm", "revoke"] and len(args) == 5:
        if device.get("revoke_ignored"):
            return 0  # simulates a change the system silently ignores
        state.setdefault("revoked", {}).setdefault(args[3], []).append(args[4])
        _save_state(serial, state)
    elif args == ["shell", "dumpsys", "account"]:
        sys.stdout.write(ACCOUNTS_OUTPUT)
    elif args == ["shell", "df", "-k", "/data"]:
        if device.get("df") == "denied":
            sys.stdout.write("df: /data: Permission denied\n")
            return 1
        sys.stdout.write(DF_OUTPUT)
    elif args == ["shell", "dumpsys", "battery"]:
        sys.stdout.write(BATTERY_OUTPUT)
    elif args[:3] == ["shell", "settings", "list"] and len(args) == 4:
        values = _settings_view(scan, state, args[3])
        sys.stdout.write("".join(f"{k}={v}\n" for k, v in values.items()))
    elif args == ["shell", "pm", "list", "packages", "-3"]:
        sys.stdout.write("".join(f"package:{a['name']}\n" for a in scan.get("apps", []) if not a["system"]))
    elif args == ["shell", "pm", "list", "packages", "-d"]:
        sys.stdout.write("")
    elif args == ["shell", "dumpsys", "package", "packages"]:
        sys.stdout.write(dumpsys_packages(_apps_with_state(scan, state)))
    elif args[:3] == ["shell", "dumpsys", "package"] and len(args) == 4:
        apps = [a for a in _apps_with_state(scan, state) if a["name"] == args[3]]
        sys.stdout.write("Activity Resolver Table:\n  Non-Data Actions:\n\n" + dumpsys_packages(apps))
    elif args == ["shell", "dumpsys", "device_policy"]:
        sys.stdout.write(device_policy(scan.get("admins", []), scan.get("owner")))
    elif args == ["shell", "appops", "query-op", "REQUEST_INSTALL_PACKAGES", "allow"]:
        allowed = [p for p in scan.get("install_allowed", []) if p not in state.get("install_denied", [])]
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
            if _load_state(device["serial"]).get("global", {}).get("adb_enabled") == "0":
                continue  # adbd stopped: the phone vanished from adb
            if _load_state(device["serial"]).get("mode", "adb") != "adb":
                continue  # rebooted to the bootloader (or powered off)
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


def _fastboot_devices(config: dict) -> list[dict]:
    """Devices currently in fastboot mode (declared as such, or rebooted there from adb)."""
    devices = [d for d in config.get("fastboot", []) if _load_state(d["serial"]).get("mode", "fastboot") == "fastboot"]
    devices += [
        {**d, "state": "fastboot"} for d in config.get("adb", []) if _load_state(d["serial"]).get("mode") == "fastboot"
    ]
    return devices


def _fb_var(device: dict, state: dict, name: str) -> str | None:
    profile = device.get("profile", "pixel8pro_stock")
    base = {}
    for line in FASTBOOT_GETVAR.get(profile, FASTBOOT_GETVAR["pixel8pro_stock"]).splitlines():
        line = line.replace("(bootloader) ", "")
        if ":" in line:
            key, _, value = line.partition(":")
            base[key.strip()] = value.strip()
    base.setdefault("slot-count", "2")
    base.setdefault("max-download-size", "0xf900000")
    base["battery-soc-ok"] = device.get("battery_ok", "yes")
    base.update(state.get("fastboot_vars", {}))
    return base.get(name)


def _fastboot(args: list[str], scenario: str) -> int:
    config = _devices()
    if args == ["--version"]:
        version = "34.0.5-10900879" if scenario == "old_fastboot" else "35.0.2-12147458"
        sys.stdout.write(f"fastboot version {version}\nInstalled as /fake/fastboot\n")
        return 0
    devices = _fastboot_devices(config)
    if args in (["devices"], ["devices", "-l"]):
        for device in devices:
            sys.stdout.write(f"{device['serial']}\t{device['state']}\n")
        return 0
    if args and args[0] == "-s":
        serial, rest = args[1], args[2:]
    else:  # like the official flash-all script: target chosen by ANDROID_SERIAL (or the only device)
        serial = os.environ.get("ANDROID_SERIAL") or (devices[0]["serial"] if len(devices) == 1 else "")
        rest = args
    device = next((d for d in devices if d["serial"] == serial), None)
    if device is None:
        sys.stderr.write("< waiting for any device >\n")
        time.sleep(30)
        return 1
    state = _load_state(serial)
    done = "Finished. Total time: 0.012s\n"
    # Options used by the official flash-all.sh (--slot=other, --disable-super-optimization, ...).
    options = [a for a in rest if a.startswith("--")]
    rest = [a for a in rest if not a.startswith("--")]
    for option in options:
        if option.startswith("--set-active="):
            slot = option.split("=", 1)[1]
            current = _fb_var(device, state, "current-slot") or "a"
            new_slot = {"a": "b", "b": "a"}[current] if slot == "other" else slot
            state.setdefault("fastboot_vars", {})["current-slot"] = new_slot
            _save_state(serial, state)
            sys.stderr.write(f"Setting current slot to '{new_slot}'  OKAY [  0.050s]\n" + done)
            if not rest:
                return 0
    if rest in (["reboot-bootloader"], ["oem", "uart", "disable"], ["snapshot-update", "cancel"]):
        sys.stderr.write("OKAY [  0.100s]\n" + done)
        return 0
    if len(rest) == 2 and rest[0] == "update":
        if not Path(rest[1]).is_file():
            sys.stderr.write(f"fastboot: error: cannot open '{rest[1]}'\n")
            return 1
        sys.stderr.write("Checking 'product'  OKAY\n" + done)
        return 0
    if rest == ["getvar", "all"]:
        sys.stderr.write(FASTBOOT_GETVAR[device.get("profile", "pixel8pro_stock")])
        return 0
    if len(rest) == 2 and rest[0] == "getvar":
        value = _fb_var(device, state, rest[1])
        sys.stderr.write(
            (
                f"{rest[1]}: {value}\n"
                if value is not None
                else f"getvar:{rest[1]} FAILED (remote: 'GetVar Variable Not found')\n"
            )
            + done
        )
        return 0 if value is not None else 1
    if rest == ["flashing", "get_unlock_ability"]:
        sys.stderr.write(f"(bootloader) get_unlock_ability: {device.get('unlock_ability', 1)}\nOKAY [  0.001s]\n")
        return 0
    if rest in (["flashing", "unlock"], ["flashing", "lock"]):
        if device.get("refuse_" + rest[1]):
            sys.stderr.write(
                f"FAILED (remote: '{rest[1].capitalize()} rejected by user')\nfastboot: error: Command failed\n"
            )
            return 1
        state.setdefault("fastboot_vars", {})["unlocked"] = "yes" if rest[1] == "unlock" else "no"
        _save_state(serial, state)
        sys.stderr.write("OKAY [ 12.345s]\n" + done)
        return 0
    if rest == ["reboot"]:
        state["mode"] = "adb" if device.get("adb_after_reboot") else "off"
        _save_state(serial, state)
        sys.stderr.write("Rebooting  OKAY [  0.001s]\n" + done)
        return 0
    if rest and rest[0] in ("flash", "erase"):
        partition = rest[1]
        if partition == device.get("flash_fail_on"):
            sys.stderr.write(
                f"Sending '{partition}'  FAILED (remote: 'Partition flashing failed')\n"
                "fastboot: error: Command failed\n"
            )
            return 1
        if partition == device.get("unplug_on"):
            # Cable pulled while writing: real fastboot wording, then the phone is gone.
            state["mode"] = "off"
            _save_state(serial, state)
            sys.stderr.write(
                f"Sending '{partition}' (8192 KB)  FAILED (Write to device failed (No such device))\n"
                "fastboot: error: Command failed\n"
            )
            return 1
        if rest[0] == "flash" and not Path(rest[2]).is_file():
            sys.stderr.write(f"fastboot: error: cannot load '{rest[2]}': No such file or directory\n")
            return 1
        state.setdefault("flashed", []).append(partition)
        _save_state(serial, state)
        if device.get("flash_sleep"):
            time.sleep(device["flash_sleep"])
        verb = "Erasing" if rest[0] == "erase" else "Writing"
        sys.stderr.write(
            f"Sending '{partition}' (64 KB)  OKAY [  0.010s]\n{verb} '{partition}'  OKAY [  0.020s]\n" + done
        )
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
