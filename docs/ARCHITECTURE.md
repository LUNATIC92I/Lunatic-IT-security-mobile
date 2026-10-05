# Architecture

```
navigateur (HTML/CSS/JS)  ──HTTP 127.0.0.1──►  FastAPI (app/main.py)
                                                   │
                         app/api/*  (routes, validation des entrées)
                                                   │
                         app/core/* (services)  ──► CommandRunner ──► adb / fastboot
                                                   │                    (liste blanche, sans shell)
                         app/security/*, app/graphene/*  (phases 3 à 8)
```

## Modules livrés en phase 1

| Fichier | Rôle |
|---------|------|
| `app/config.py` | Paramètres `LMS_*` validés (loopback uniquement, source GrapheneOS HTTPS officielle), répertoires par plateforme. |
| `app/logging_config.py` | Format `AAAA-MM-JJ HH:MM:SS NIVEAU message`, masquage des secrets et des numéros de série, tampon mémoire pour `/api/logs`. |
| `app/core/errors.py` | Erreurs utilisateur `ERREUR / CAUSE POSSIBLE / ACTION`. |
| `app/core/safety.py` | Validation des numéros de série, masquage, protection path traversal. |
| `app/core/platform_tools.py` | Localisation d'adb/fastboot, **liste blanche des commandes**, exécution `subprocess` sécurisée, détection de version. |
| `app/core/environment.py` | Diagnostic de l'ordinateur (Python, disque, outils, udev, fwupd, pilote Windows). |
| `app/core/audit_logger.py` | Journal d'audit JSONL chaîné par SHA-256 (falsification détectable). |
| `app/api/routes.py` | `/api/health`, `/api/session`, `/api/system/environment`, `/api/settings`, `/api/logs`, `/api/audit`, `/api/audit/verify`. |
| `app/main.py` | Fabrique `create_app`, middlewares de sécurité, CLI (`--check`, `--json`, `--port`, `--no-browser`). |
| `frontend/` | Shell de l'interface : Dashboard (diagnostic), Logs temps réel, Paramètres + audit. |

## Modules livrés en phase 2

| Fichier | Rôle |
|---------|------|
| `app/core/adb_manager.py` | Parsing de `adb devices -l`, `getprop` (liste blanche de propriétés, numéros de série écartés), `df -k /data`, `dumpsys battery`, `settings get`. |
| `app/core/fastboot_manager.py` | Parsing de `fastboot devices` et `fastboot getvar all` (lecture seule). |
| `app/core/device_manager.py` | États de connexion → message + action, identifiants opaques, sélection de l'appareil cible, détails, audit des connexions/déconnexions. |
| `app/models/device.py` | Modèles Pydantic `DeviceStatus`, `DeviceConnection`, `DeviceDetails`. |
| `app/api/device_routes.py` | `GET /api/device/status`, `GET /api/device`, `POST /api/device/adb/restart-server`. |
| `frontend/js/devices.js` | Vue Appareils : liste, sélection, détails, redémarrage ADB avec confirmation. |

### Identifiants d'appareil
Le navigateur ne reçoit jamais le numéro de série : seulement sa forme masquée
(`HU•••••••••01`) et un `device_id` = HMAC-SHA256(numéro de série, clé aléatoire
générée à chaque lancement), tronqué à 16 caractères hexadécimaux. Le backend
retrouve le numéro de série à partir d'une énumération fraîche ; un identifiant
inconnu (appareil débranché) ou mal formé est refusé.

### Sélection de l'appareil cible
Sans `device_id`, l'opération cible l'unique appareil prêt. S'il y en a plusieurs,
la requête est refusée (`multiple_devices`) ; s'il n'y en a aucun, l'erreur
explique quoi faire selon l'état (non autorisé, hors ligne, accès USB refusé…).

## Exécution des commandes

Aucune ligne de commande n'est construite à partir d'une saisie libre. Un module
appelle `runner.run("adb.devices")` ; le nom référence une entrée de
`COMMAND_WHITELIST`, dont le gabarit est fixe. Les parties variables sont des
`Arg` validées par expression régulière (pas de `-` initial, pas d'espace ni de
métacaractère). Le numéro de série est injecté via `-s` après validation.
Les commandes marquées `destructive=True` exigent `confirmed=True`.
`subprocess.run` est toujours appelé avec une liste d'arguments, `shell=False`,
`stdin=DEVNULL` et un timeout ; le processus est tué à expiration.

## Modules livrés en phase 3 — Security Scanner

```
AuditCollector (android_audit.py) ── commandes ADB en lecture seule ──► DeviceSnapshot
        │
        ├─ analyze_system            (android_audit.py)  débogage, options développeur, sources inconnues
        ├─ boot_security             bootloader, Verified Boot, SELinux, root, build de debug, clés de test
        ├─ encryption                ro.crypto.state / type
        ├─ updates                   âge du correctif, version Android maintenue
        ├─ network                   proxy, DNS privé, Wi-Fi, VPN, ADB sans fil
        ├─ applications              origine, installations récentes
        └─ permissions               groupes sensibles, accès spéciaux, score contextuel par application
                │
        recommendations.py ── score 0-100, note, tri ──► SecurityReport
```

| Fichier | Rôle |
|---------|------|
| `app/security/android_audit.py` | Collecte (une étape par source, chaque échec devient une *limite*), constats « système », orchestration `run_audit`. Abandon propre si le téléphone disparaît pendant l'analyse. |
| `app/security/applications.py` | Parsing de `dumpsys package packages` (utilisateur 0 uniquement, paquets cachés ignorés) et de `pm list packages`. |
| `app/security/permissions.py` | Groupes de permissions, `device_policy`, `appops`, services d'accessibilité / écouteurs de notifications, score de risque par application. |
| `app/security/network.py` | `cmd wifi status`, `dumpsys connectivity`, paramètres proxy / DNS / VPN. SSID, BSSID, MAC et IP ne sont pas conservés. |
| `app/security/boot_security.py`, `encryption.py`, `updates.py` | Sections et constats correspondants. |
| `app/security/recommendations.py` | Calcul du score. |
| `app/core/security_scanner.py` | Analyse en tâche de fond (une à la fois), progression, rapports en mémoire et sur disque, sections à la demande. |
| `app/api/security_routes.py` | Endpoints de sécurité. |
| `frontend/js/security.js` | Vues Security Scan, Applications, Permissions, Réseau, Chiffrement, Bootloader, Mises à jour. |

### Score
Chaque constat retire des points selon sa gravité (critique 35, élevée 15, moyenne 6,
faible 2, info 0). La pénalité est plafonnée par catégorie (système 30, démarrage 50,
applications 15, permissions 25, réseau 20, chiffrement 40, mises à jour 30) pour que
de nombreux constats mineurs du même type ne suffisent pas à faire tomber le score.
Un constat critique plafonne le score à 39, un constat élevé à 74.
Notes : 90-100 Excellent, 75-89 Bon, 60-74 Moyen, 40-59 Faible, 0-39 Critique.

### Score contextuel des applications
Une permission n'est jamais considérée comme malveillante en soi. Le score d'une
application tierce cumule des poids par capacité (micro 10, localisation en
arrière-plan 12, SMS 12…), par accès spécial (accessibilité 30, lecture des
notifications 18, administrateur 15…), son origine (hors magasin +15) et des
combinaisons (origine non vérifiée + nombreuses permissions +10). Le contexte
réduit le poids (accès SMS de l'application SMS par défaut). Les applications
système ne sont pas notées.

### Confidentialité
Seules des listes blanches de propriétés et de paramètres sont conservées
(`android_id`, nom de l'appareil, adresse Bluetooth sont écartés). Les rapports
sauvegardés dans `<données>/reports/` (permissions 0600) ne contiennent que le
numéro de série masqué.
