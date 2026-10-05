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
