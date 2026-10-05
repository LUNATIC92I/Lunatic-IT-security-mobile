from app.core import adb_manager, fastboot_manager
from tests.fakes.profiles import BATTERY_OUTPUT, DF_OUTPUT, FASTBOOT_GETVAR, getprop_output


def test_parse_adb_devices_all_states():
    output = (
        "* daemon not running; starting now at tcp:5037\n"
        "* daemon started successfully\n"
        "List of devices attached\n"
        "0A1B2C3D4E             device usb:1-1 product:husky model:Pixel_8_Pro device:husky transport_id:1\n"
        "1B2C3D4E5F             unauthorized usb:1-2 transport_id:2\n"
        "192.168.1.20:5555      offline transport_id:3\n"
        "2C3D4E5F6A             no permissions (missing udev rules? user is in the plugdev group); "
        "see [http://developer.android.com/tools/device.html]\n"
        "emulator-5554          device product:sdk_gphone64 model:sdk device:emu64 transport_id:4\n"
        "\n"
    )
    entries = adb_manager.parse_devices(output)
    assert [(e.serial, e.state) for e in entries] == [
        ("0A1B2C3D4E", "device"),
        ("1B2C3D4E5F", "unauthorized"),
        ("192.168.1.20:5555", "offline"),
        ("2C3D4E5F6A", "no permissions"),
        ("emulator-5554", "device"),
    ]
    assert entries[0].attributes == {
        "usb": "1-1",
        "product": "husky",
        "model": "Pixel_8_Pro",
        "device": "husky",
        "transport_id": "1",
    }


def test_parse_adb_devices_empty():
    assert adb_manager.parse_devices("List of devices attached\n\n") == []


def test_parse_getprop_keeps_allowlist_only():
    props = adb_manager.parse_getprop(getprop_output("pixel8pro_stock"))
    assert props["ro.product.model"] == "Pixel 8 Pro"
    assert props["ro.boot.verifiedbootstate"] == "green"
    assert "ro.serialno" not in props and "ro.boot.serialno" not in props
    assert "persist.sys.timezone" not in props


def test_parse_df_normal_and_wrapped():
    assert adb_manager.parse_df(DF_OUTPUT) == (236107512 * 1024, 41210988 * 1024, 194765452 * 1024)
    wrapped = "Filesystem 1K-blocks Used Available Use% Mounted on\n/dev/block/bootdevice/by-name/userdata\n 1000 400 600 40% /data\n"
    assert adb_manager.parse_df(wrapped) == (1024000, 409600, 614400)
    assert adb_manager.parse_df("df: /data: Permission denied\n") is None
    assert adb_manager.parse_df("") is None


def test_parse_battery():
    battery = adb_manager.parse_battery(BATTERY_OUTPUT)
    assert battery == {"level": 78, "status": "en charge", "health": "bonne", "temperature_c": 28.6, "plugged": True}
    assert adb_manager.parse_battery("garbage") is None


def test_parse_fastboot_devices():
    output = "0A1B2C3D4E\tfastboot\nno permissions; see [http://developer.android.com/tools/device.html]\tfastboot\n"
    entries = fastboot_manager.parse_devices(output)
    assert (entries[0].serial, entries[0].state) == ("0A1B2C3D4E", "fastboot")
    assert entries[1].state == "no permissions"


def test_parse_getvar_all():
    variables = fastboot_manager.parse_getvar_all(FASTBOOT_GETVAR["pixel8pro_stock"])
    assert variables["product"] == "husky"
    assert variables["unlocked"] == "no"
    assert variables["current-slot"] == "a"
    assert "serialno" not in variables and "partition-size:boot_a" not in variables


def test_parse_getvar_single_format():
    assert fastboot_manager.parse_getvar_all("product: husky\nFinished. Total time: 0.001s\n") == {"product": "husky"}
