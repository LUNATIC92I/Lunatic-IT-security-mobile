"""Security audit data models."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(str, Enum):
    SYSTEM = "system"
    BOOT = "boot"
    APPLICATIONS = "applications"
    PERMISSIONS = "permissions"
    NETWORK = "network"
    ENCRYPTION = "encryption"
    UPDATES = "updates"


CATEGORY_LABELS = {
    Category.SYSTEM: "Système",
    Category.BOOT: "Démarrage sécurisé",
    Category.APPLICATIONS: "Applications",
    Category.PERMISSIONS: "Permissions",
    Category.NETWORK: "Réseau",
    Category.ENCRYPTION: "Chiffrement",
    Category.UPDATES: "Mises à jour",
}


class Finding(BaseModel):
    """One recommendation: problem, severity, why it matters, evidence, fix."""

    id: str
    category: Category
    severity: Severity
    title: str = Field(description="Problème")
    why: str = Field(description="Pourquoi c'est important")
    evidence: str = Field(description="Preuve technique")
    recommendation: str
    remediation: str = Field(description="Méthode de correction")
    hardening_action: str | None = Field(
        default=None, description="Identifiant de l'action de l'assistant de renforcement, si applicable"
    )
    affected: list[str] = Field(default_factory=list)


class CategoryScore(BaseModel):
    category: Category
    label: str
    penalty: float
    max_penalty: float
    score: int
    findings: int


class AppInfo(BaseModel):
    package: str
    version: str | None = None
    system: bool
    enabled: bool = True
    installer: str | None = None
    installer_label: str
    sideloaded: bool = False
    first_install: str | None = None
    last_update: str | None = None
    recently_installed: bool = False
    target_sdk: int | None = None
    granted_groups: list[str] = Field(default_factory=list)
    granted_permissions: list[str] = Field(default_factory=list)
    special_access: list[str] = Field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "low"
    risk_reasons: list[str] = Field(default_factory=list)


class ApplicationsSection(BaseModel):
    total: int
    third_party: int
    system: int
    disabled: int
    sideloaded: int
    recently_installed: int
    apps: list[AppInfo]


class PermissionGroupSummary(BaseModel):
    group: str
    label: str
    third_party_apps: list[str]
    system_apps_count: int


class PermissionsSection(BaseModel):
    groups: list[PermissionGroupSummary]
    special_access: dict[str, list[str]]
    default_sms_app: str | None = None


class NetworkSection(BaseModel):
    wifi_enabled: bool | None = None
    wifi_connected: bool | None = None
    wifi_security: str | None = None
    active_transports: list[str] = Field(default_factory=list)
    internet_validated: bool | None = None
    vpn_active: bool | None = None
    always_on_vpn_app: str | None = None
    vpn_lockdown: bool | None = None
    proxy: str | None = None
    private_dns_mode: str | None = None
    private_dns_host: str | None = None
    dns_servers: list[str] = Field(default_factory=list)
    airplane_mode: bool | None = None
    bluetooth_enabled: bool | None = None
    adb_over_wifi: bool | None = None


class UpdatesSection(BaseModel):
    android_version: str | None = None
    sdk_version: int | None = None
    security_patch: str | None = None
    security_patch_age_days: int | None = None
    vendor_security_patch: str | None = None
    status: str
    supported_android: bool | None = None
    update_check: str


class BootSection(BaseModel):
    bootloader_locked: bool | None = None
    verified_boot_state: str | None = None
    verified_boot_label: str | None = None
    oem_unlock_allowed: bool | None = None
    selinux: str | None = None
    build_type: str | None = None
    build_tags: str | None = None
    debuggable: bool | None = None
    su_binary: str | None = None


class EncryptionSection(BaseModel):
    state: str | None = None
    type: str | None = None
    label: str


class SecurityReport(BaseModel):
    report_id: str
    created_at: str
    duration_seconds: float
    device_id: str
    serial_masked: str
    manufacturer: str | None = None
    model: str | None = None
    codename: str | None = None
    android_version: str | None = None
    score: int
    grade: str
    grade_label: str
    categories: list[CategoryScore]
    findings: list[Finding]
    severity_counts: dict[str, int]
    boot: BootSection
    encryption: EncryptionSection
    updates: UpdatesSection
    network: NetworkSection
    applications: ApplicationsSection
    permissions: PermissionsSection
    limitations: list[str]
