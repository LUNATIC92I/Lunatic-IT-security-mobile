"""Network configuration audit (passive, read-only).

Sources: ``settings list global/secure`` (proxy, private DNS, always-on VPN,
airplane mode, Bluetooth, ADB over Wi-Fi), ``cmd wifi status`` (Android 11+)
and ``dumpsys connectivity`` (active transports, DNS servers).

No scan of any network is performed. Wi-Fi names (SSID), BSSID, MAC and IP
addresses are deliberately not kept.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from app.models.security_report import Category, Finding, NetworkSection, Severity

# android.net.wifi.WifiInfo security types
WIFI_SECURITY_TYPES = {
    0: "Ouvert (aucun chiffrement)",
    1: "WEP (obsolète)",
    2: "WPA2-Personnel (PSK)",
    3: "WPA2/WPA3-Entreprise (EAP)",
    4: "WPA3-Personnel (SAE)",
    5: "WPA3-Entreprise 192 bits",
    6: "Enhanced Open (OWE)",
    7: "WAPI-PSK",
    8: "WAPI-CERT",
    9: "WPA3-Entreprise",
    10: "OSEN",
    11: "Passpoint",
    12: "Passpoint R3",
    13: "DPP (Easy Connect)",
}
WEAK_WIFI = {0, 1}


@dataclass
class WifiStatus:
    enabled: bool | None = None
    connected: bool | None = None
    security_type: int | None = None


@dataclass
class ConnectivityStatus:
    transports: list[str] = field(default_factory=list)
    validated: bool | None = None
    dns_servers: list[str] = field(default_factory=list)


def parse_wifi_status(output: str) -> WifiStatus:
    status = WifiStatus()
    if re.search(r"^Wifi is enabled", output, re.MULTILINE):
        status.enabled = True
    elif re.search(r"^Wifi is disabled", output, re.MULTILINE):
        status.enabled = False
    if re.search(r"Wifi is connected to", output):
        status.connected = True
    elif re.search(r"Wifi is not connected", output) or status.enabled is False:
        status.connected = False
    match = re.search(r"Security type: (\d+)", output)
    if match and status.connected:
        status.security_type = int(match.group(1))
    return status


_NAI_RE = re.compile(r"^\s*NetworkAgentInfo\{")


def parse_connectivity(output: str) -> ConnectivityStatus:
    """Extract transports of connected networks and DNS servers of the default one."""
    status = ConnectivityStatus()
    default_net = re.search(r"Active default network:\s*(\d+)", output)
    default_id = default_net.group(1) if default_net else None
    for line in output.splitlines():
        if not _NAI_RE.match(line) or "CONNECTED" not in line:
            continue
        transports = re.search(r"Transports:\s*([A-Z_|]+)", line)
        if transports:
            for transport in transports.group(1).split("|"):
                if transport and transport not in status.transports:
                    status.transports.append(transport)
        is_default = default_id is not None and re.search(rf"network\{{{default_id}\}}", line)
        if is_default or (default_id is None and status.validated is None):
            caps = re.search(r"Capabilities:\s*(\S+)", line)
            if caps:
                status.validated = "VALIDATED" in caps.group(1).split("&")
            dns = re.search(r"DnsAddresses:\s*\[([^\]]*)\]", line)
            if dns:
                for entry in dns.group(1).split(","):
                    address = entry.strip().lstrip("/")
                    try:
                        ipaddress.ip_address(address)
                    except ValueError:
                        continue
                    if address not in status.dns_servers:
                        status.dns_servers.append(address)
    return status


def _flag(value: str | None) -> bool | None:
    if value in (None, "null", ""):
        return None
    return value.strip() not in ("0", "false")


def build_network_section(
    global_settings: dict[str, str],
    secure_settings: dict[str, str],
    wifi: WifiStatus | None,
    connectivity: ConnectivityStatus | None,
) -> NetworkSection:
    proxy = global_settings.get("http_proxy")
    if proxy in (None, "", ":0", "null"):
        host = global_settings.get("global_http_proxy_host")
        proxy = f"{host}:{global_settings.get('global_http_proxy_port', '')}".rstrip(":") if host else None
    always_on = secure_settings.get("always_on_vpn_app")
    return NetworkSection(
        wifi_enabled=wifi.enabled if wifi else _flag(global_settings.get("wifi_on")),
        wifi_connected=wifi.connected if wifi else None,
        wifi_security=WIFI_SECURITY_TYPES.get(wifi.security_type) if wifi and wifi.security_type is not None else None,
        active_transports=connectivity.transports if connectivity else [],
        internet_validated=connectivity.validated if connectivity else None,
        vpn_active=("VPN" in connectivity.transports) if connectivity else None,
        always_on_vpn_app=always_on if always_on not in (None, "", "null") else None,
        vpn_lockdown=_flag(secure_settings.get("always_on_vpn_lockdown")),
        proxy=proxy,
        private_dns_mode=global_settings.get("private_dns_mode"),
        private_dns_host=global_settings.get("private_dns_specifier") or None,
        dns_servers=connectivity.dns_servers if connectivity else [],
        airplane_mode=_flag(global_settings.get("airplane_mode_on")),
        bluetooth_enabled=_flag(global_settings.get("bluetooth_on")),
        adb_over_wifi=_flag(global_settings.get("adb_wifi_enabled")),
    )


def analyze_network(section: NetworkSection, wifi: WifiStatus | None) -> list[Finding]:
    findings: list[Finding] = []
    if section.proxy:
        findings.append(
            Finding(
                id="network.proxy",
                category=Category.NETWORK,
                severity=Severity.MEDIUM,
                title="Un proxy HTTP global est configuré",
                why="Tout le trafic web peut transiter par ce proxy, qui peut l'observer ou le modifier "
                "(notamment avec un certificat racine installé). Normal en entreprise, suspect sinon.",
                evidence=f"settings global http_proxy = {section.proxy}",
                recommendation="Supprimez le proxy si vous ne l'avez pas configuré volontairement.",
                remediation="Paramètres › Réseau › Wi-Fi › (réseau) › Proxy : Aucun. Un proxy global défini par ADB "
                "se retire avec l'assistant de renforcement.",
                hardening_action="clear_global_proxy",
            )
        )
    if wifi and wifi.security_type in WEAK_WIFI:
        findings.append(
            Finding(
                id="network.weak_wifi",
                category=Category.NETWORK,
                severity=Severity.MEDIUM,
                title="Connecté à un Wi-Fi non chiffré ou en WEP",
                why="Sur un réseau ouvert ou WEP, les autres utilisateurs peuvent intercepter le trafic non chiffré "
                "et usurper le point d'accès.",
                evidence=f"cmd wifi status : Security type {wifi.security_type} "
                f"({WIFI_SECURITY_TYPES.get(wifi.security_type)})",
                recommendation="Utilisez un réseau WPA2/WPA3 ou un VPN de confiance sur ce réseau.",
                remediation="Paramètres › Réseau › Wi-Fi : oubliez ce réseau ou activez un VPN.",
            )
        )
    if section.private_dns_mode in (None, "off"):
        findings.append(
            Finding(
                id="network.private_dns",
                category=Category.NETWORK,
                severity=Severity.LOW,
                title="DNS privé (chiffré) désactivé",
                why="Sans DNS chiffré, les noms de domaines consultés circulent en clair et peuvent être "
                "observés ou falsifiés par le réseau local ou l'opérateur.",
                evidence=f"settings global private_dns_mode = {section.private_dns_mode or 'non défini'}",
                recommendation="Activez le DNS privé en mode automatique ou avec un fournisseur de confiance.",
                remediation="Paramètres › Réseau et Internet › DNS privé › Automatique (ou nom d'hôte du fournisseur).",
                hardening_action="enable_private_dns",
            )
        )
    if section.adb_over_wifi:
        findings.append(
            Finding(
                id="network.adb_wifi",
                category=Category.NETWORK,
                severity=Severity.MEDIUM,
                title="Débogage ADB sans fil activé",
                why="Le débogage sans fil expose ADB sur le réseau Wi-Fi : un ordinateur appairé peut contrôler "
                "le téléphone à distance.",
                evidence="settings global adb_wifi_enabled = 1",
                recommendation="Désactivez le débogage sans fil quand vous ne l'utilisez pas.",
                remediation="Options pour les développeurs › Débogage sans fil : désactiver.",
                hardening_action="disable_adb_wifi",
            )
        )
    return findings
