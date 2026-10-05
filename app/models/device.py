"""Device data models exposed through the API.

Serial numbers never leave the backend in clear: the UI receives a masked
serial for display and an opaque ``device_id`` (HMAC of the serial with a
per-launch key) to reference a device in later requests.

Every optional field is ``None`` when Android does not expose the value to
ADB; the matching reason is listed in ``unavailable``.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Transport(str, Enum):
    ADB = "adb"
    FASTBOOT = "fastboot"


class ConnectionState(str, Enum):
    DEVICE = "device"  # authorized, ADB fully usable
    UNAUTHORIZED = "unauthorized"
    OFFLINE = "offline"
    NO_PERMISSIONS = "no_permissions"
    AUTHORIZING = "authorizing"
    CONNECTING = "connecting"
    RECOVERY = "recovery"
    SIDELOAD = "sideload"
    RESCUE = "rescue"
    BOOTLOADER = "bootloader"
    FASTBOOT = "fastboot"
    UNKNOWN = "unknown"


class DeviceConnection(BaseModel):
    device_id: str
    serial_masked: str
    transport: Transport
    state: ConnectionState
    ready: bool = Field(description="True when the device can be inspected through this transport")
    model_hint: str | None = None
    product_hint: str | None = None
    codename_hint: str | None = None
    usb: str | None = None
    message: str
    action: str | None = None


class DeviceStatus(BaseModel):
    adb_available: bool
    fastboot_available: bool
    adb_error: dict | None = None
    fastboot_error: dict | None = None
    devices: list[DeviceConnection]
    summary: str = Field(description="none | single | multiple")
    ready_count: int
    message: str


class BootloaderInfo(BaseModel):
    locked: bool | None = None
    verified_boot_state: str | None = None
    verified_boot_label: str | None = None
    vbmeta_device_state: str | None = None
    oem_unlock_supported: bool | None = None
    oem_unlock_allowed: bool | None = None
    source: str = "adb"


class EncryptionInfo(BaseModel):
    state: str | None = None
    type: str | None = None
    label: str


class StorageInfo(BaseModel):
    total_bytes: int
    used_bytes: int
    free_bytes: int


class BatteryInfo(BaseModel):
    level: int | None = None
    status: str | None = None
    health: str | None = None
    temperature_c: float | None = None
    plugged: bool | None = None


class DeviceDetails(BaseModel):
    device_id: str
    serial_masked: str
    transport: Transport
    state: ConnectionState
    manufacturer: str | None = None
    brand: str | None = None
    model: str | None = None
    codename: str | None = None
    is_google_pixel: bool = False
    android_version: str | None = None
    sdk_version: int | None = None
    build_id: str | None = None
    build_display: str | None = None
    build_type: str | None = None
    build_tags: str | None = None
    security_patch: str | None = None
    security_patch_age_days: int | None = None
    adb_enabled: bool | None = None
    usb_debugging: bool | None = None
    developer_options: bool | None = None
    bootloader: BootloaderInfo
    encryption: EncryptionInfo | None = None
    integrity: str
    storage: StorageInfo | None = None
    battery: BatteryInfo | None = None
    bootloader_version: str | None = None
    baseband_version: str | None = None
    current_slot: str | None = None
    unavailable: list[str] = Field(default_factory=list)
