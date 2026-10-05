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

## Exécution des commandes

Aucune ligne de commande n'est construite à partir d'une saisie libre. Un module
appelle `runner.run("adb.devices")` ; le nom référence une entrée de
`COMMAND_WHITELIST`, dont le gabarit est fixe. Les parties variables sont des
`Arg` validées par expression régulière (pas de `-` initial, pas d'espace ni de
métacaractère). Le numéro de série est injecté via `-s` après validation.
Les commandes marquées `destructive=True` exigent `confirmed=True`.
`subprocess.run` est toujours appelé avec une liste d'arguments, `shell=False`,
`stdin=DEVNULL` et un timeout ; le processus est tué à expiration.
