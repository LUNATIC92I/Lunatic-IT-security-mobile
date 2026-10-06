# LUNATIC MOBILE SECURITY

Logiciel desktop (backend Python / interface HTML-CSS-JS) pour auditer la
sécurité des smartphones Android et guider l'installation **officielle** de
GrapheneOS sur les Google Pixel compatibles.

> **État : phases 1 à 5 livrées** — architecture, journalisation, audit,
> exécution sécurisée d'ADB/Fastboot, diagnostic de l'environnement,
> détection des appareils, scanner de sécurité avec score, assistant de
> renforcement et sauvegarde vérifiée. GrapheneOS arrive dans les phases suivantes (voir [docs/ROADMAP.md](docs/ROADMAP.md)).
> L'interface n'affiche que ce qui fonctionne réellement.

## Sommaire
- [Fonctionnalités disponibles](#fonctionnalités-disponibles)
- [Architecture](#architecture)
- [Prérequis](#prérequis)
- [Installation](#installation)
- [Installation Android Platform Tools](#installation-android-platform-tools)
- [Lancement](#lancement)
- [Configuration](#configuration)
- [Avertissements](#avertissements)
- [Dépannage](#dépannage)
- [Tests et développement](#tests-et-développement)
- [Sécurité](#sécurité)
- [Licence](#licence)

## Fonctionnalités disponibles

- **Diagnostic de l'environnement** (Dashboard et `--check`) : version de Python,
  répertoire de données accessible, espace disque (une image GrapheneOS
  nécessite plusieurs Go), présence et version d'`adb` et `fastboot`
  (fastboot **≥ 35.0.1** exigé par GrapheneOS), règles udev pour les Pixel et
  service `fwupd` sous Linux, rappel du pilote USB Google sous Windows.
- **Exécution sécurisée d'ADB/Fastboot** : liste blanche de commandes,
  arguments validés, jamais de shell, timeouts, processus tué en cas de blocage.
- **Détection des appareils** (page Appareils) via ADB et Fastboot, actualisée
  automatiquement : constructeur, modèle, codename, version Android, SDK, build,
  numéro de série **masqué**, état ADB / débogage USB / options développeur,
  bootloader (verrouillé ou non), Verified Boot, chiffrement, patch de sécurité
  (avec son ancienneté), niveau d'intégrité, stockage, batterie. Les cas « aucun
  appareil », « non autorisé », « hors ligne », « accès USB refusé », recovery,
  Fastboot et « plusieurs appareils » sont expliqués avec l'action à mener.
  Tout est en lecture seule ; ce qu'Android n'expose pas est listé dans
  « Limites de l'analyse » au lieu d'être deviné.
- **Security Scan** : audit en lecture seule (système, démarrage sécurisé,
  applications, permissions, réseau, chiffrement, mises à jour), **score de 0 à
  100** (Excellent / Bon / Moyen / Faible / Critique) et recommandations
  détaillées : problème, gravité, pourquoi c'est important, preuve technique,
  recommandation, méthode de correction. Rapports sauvegardés en JSON.
  Vues dédiées : Applications (origine, installations récentes, score de risque
  contextuel), Permissions (caméra, micro, localisation, SMS, contacts,
  téléphone, stockage, accessibilité, notifications, administrateur,
  installation d'applications, VPN), Réseau, Chiffrement, Bootloader,
  Mises à jour. Voir [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) pour le calcul du score.
- **Renforcement** : assistant qui propose les corrections applicables au
  téléphone connecté (désactiver un service d'accessibilité, retirer le droit
  d'installer des applications ou une permission sensible, supprimer un proxy
  global, activer le DNS privé, désactiver ADB sans fil, réactiver la
  vérification des installations USB, désactiver le débogage USB en dernier).
  Chaque action affiche **[AVANT] / [APRÈS] / [RISQUE]**, demande une
  confirmation, est appliquée seule puis **vérifiée par relecture** sur le
  téléphone. Une liste de vérifications manuelles couvre le reste (patch,
  bootloader, applications sensibles, administrateurs, notifications, comptes —
  types uniquement —, réseau, code de verrouillage).
- **Logs en temps réel** dans l'interface, au format
  `2026-10-05 17:00:02 INFO Device detected`, sans secrets ni numéros de série en clair.
- **Journal d'audit infalsifiable** (chaîne SHA-256) avec vérification d'intégrité depuis l'interface.
- **Erreurs compréhensibles** : chaque erreur affiche `ERREUR`, `CAUSE POSSIBLE` et `ACTION`.

## Architecture

```
app/
  main.py              point d'entrée, serveur FastAPI, CLI
  config.py            paramètres LMS_* validés
  logging_config.py    logs structurés et masqués
  api/routes.py        endpoints système / logs / audit
  core/
    platform_tools.py  liste blanche + exécution adb/fastboot
    environment.py     diagnostic de l'ordinateur
    audit_logger.py    audit chaîné SHA-256
    errors.py          erreurs utilisateur
    safety.py          validation, masquage, path traversal
  security/ graphene/ models/   (phases 2 à 8)
frontend/              index.html, css/, js/
tests/                 tests pytest + faux adb/fastboot exécutables
scripts/install.ps1    installation Windows
install.sh             installation Linux/macOS
docs/                  architecture, sécurité, feuille de route
```

Détails : [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Prérequis

| | Linux | macOS | Windows |
|---|---|---|---|
| Python | 3.10+ (`python3-venv` sous Debian/Ubuntu) | 3.10+ | 3.10+ (python.org, « Add to PATH ») |
| Platform Tools | standalone officiel ou `android-tools` (Arch) | standalone officiel | standalone officiel |
| USB | règles udev (voir Dépannage) | — | pilote USB Google |
| Navigateur | tout navigateur récent | idem | idem |

La plateforme est détectée automatiquement.

## Installation

Linux / macOS :
```bash
git clone <url-du-dépôt> lunatic_mobile_security
cd lunatic_mobile_security
./install.sh            # ou ./install.sh --dev pour les outils de test
```

Windows (PowerShell) :
```powershell
powershell -ExecutionPolicy Bypass -File scripts\install.ps1
```

Installation manuelle : `python -m venv .venv`, puis
`.venv/bin/pip install -r requirements.txt` (Windows : `.venv\Scripts\pip`).
Le projet peut aussi s'installer avec `pip install -e .` (commande
`lunatic-mobile-security`).

## Installation Android Platform Tools

Utilisez la version **standalone officielle** de Google. Les paquets Debian/Ubuntu
sont obsolètes et inutilisables pour GrapheneOS. Commandes et empreintes reprises
du [guide officiel GrapheneOS](https://grapheneos.org/install/cli#standalone-platform-tools) :

```bash
# Linux
curl -O https://dl.google.com/android/repository/platform-tools_r35.0.2-linux.zip
echo 'acfdcccb123a8718c46c46c059b2f621140194e5ec1ac9d81715be3d6ab6cd0a  platform-tools_r35.0.2-linux.zip' | sha256sum -c
bsdtar xvf platform-tools_r35.0.2-linux.zip      # ou: unzip

# macOS
curl -O https://dl.google.com/android/repository/platform-tools_r35.0.2-darwin.zip
echo 'SHA256 (platform-tools_r35.0.2-darwin.zip) = 1820078db90bf21628d257ff052528af1c61bb48f754b3555648f5652fa35d78' | shasum -c
tar xvf platform-tools_r35.0.2-darwin.zip
```
```powershell
# Windows
curl.exe -O https://dl.google.com/android/repository/platform-tools_r35.0.2-win.zip
(Get-FileHash platform-tools_r35.0.2-win.zip).hash -eq "2975a3eac0b19182748d64195375ad056986561d994fffbdc64332a516300bb9"
tar xvf platform-tools_r35.0.2-win.zip
```

N'extrayez l'archive que si la vérification affiche `OK` / `True`. Indiquez
ensuite le dossier au logiciel, au choix :
- variable `LMS_PLATFORM_TOOLS_DIR=/chemin/vers/platform-tools` (ou dans `.env`) ;
- copie du dossier dans `<répertoire de données>/platform-tools` ;
- ajout du dossier au `PATH`.

Contrôle : `python -m app.main --check` doit afficher Fastboot `35.0.2-…` en ✓.

## Lancement

```bash
.venv/bin/python -m app.main               # ouvre l'interface dans le navigateur
.venv/bin/python -m app.main --no-browser  # serveur seul, ouvrir http://127.0.0.1:8765/
.venv/bin/python -m app.main --port 9000
.venv/bin/python -m app.main --check       # diagnostic texte (code retour 1 si un prérequis manque)
.venv/bin/python -m app.main --check --json
```

Arrêt : `Ctrl+C` (l'arrêt est enregistré dans le journal d'audit).

## Configuration

Variables `LMS_*` ou fichier `.env` à la racine (modèle : [.env.example](.env.example)).

| Variable | Défaut | Remarque |
|----------|--------|----------|
| `LMS_HOST` | `127.0.0.1` | loopback uniquement, toute autre valeur est refusée |
| `LMS_PORT` | `8765` | 1024-65535 |
| `LMS_DATA_DIR` | voir ci-dessous | logs, téléchargements, sauvegardes |
| `LMS_PLATFORM_TOOLS_DIR` | — | dossier contenant adb/fastboot |
| `LMS_LOG_LEVEL` | `INFO` | DEBUG, INFO, WARN, ERROR, CRITICAL |
| `LMS_COMMAND_TIMEOUT` | `30` | secondes |
| `LMS_FLASH_TIMEOUT` | `900` | secondes |
| `LMS_OPEN_BROWSER` | `true` | |
| `LMS_GRAPHENEOS_RELEASES_URL` | `https://releases.grapheneos.org` | HTTPS et hôte officiel obligatoires |

Répertoire de données par défaut : `~/.local/share/lunatic-mobile-security` (Linux),
`~/Library/Application Support/LunaticMobileSecurity` (macOS),
`%LOCALAPPDATA%\LunaticMobileSecurity` (Windows). Logs : `logs/lunatic.log`
(rotation 5 × 5 Mo) et `logs/audit.jsonl`.

## Security Scan

1. Branchez le téléphone (débogage USB autorisé), ouvrez **Security Scan**.
2. Cliquez sur **Lancer l'analyse** : la progression s'affiche étape par étape
   (quelques secondes ; jusqu'à une minute avec plusieurs centaines d'applications).
3. Lisez les recommandations, les plus graves en premier. Chaque carte contient
   la preuve technique (commande et valeur lue) et la méthode de correction.

L'analyse **ne modifie rien** sur le téléphone. Ce qu'ADB ne permet pas de
vérifier est listé dans « Limites de l'analyse » : code de verrouillage,
certificats installés par l'utilisateur, comptes, mise à jour en attente,
attestation matérielle, contenu des applications (ce n'est pas un antivirus).

API : `POST /api/security/scan`, `GET /api/security/scan`, `GET /api/security/report`,
`GET /api/applications`, `GET /api/permissions`, `GET /api/network`, `GET /api/updates`,
`GET /api/security/boot`, `GET /api/security/encryption` (paramètre optionnel `device_id`).

## Backup

1. Ouvrez **Backup** : la taille de chaque dossier du stockage partagé s'affiche.
2. Cochez les dossiers (Photos/DCIM, Images, Documents, Téléchargements…) et, si
   besoin, les **APK des applications tierces** (pour les réinstaller).
3. Choisissez le dossier de destination (**Parcourir…**) ; l'espace libre est contrôlé.
4. **Démarrer** : progression, nombre de fichiers vérifiés, annulation possible
   (les fichiers partiels sont alors supprimés).
5. Résultat : « SHA-256 vérifié » uniquement si chaque fichier copié est
   identique à l'original (empreinte calculée sur le téléphone puis sur
   l'ordinateur). Sinon, la liste précise des anomalies est affichée.

Chaque sauvegarde contient `SHA256SUMS` et `backup.json`. Vous pouvez la
revérifier à tout moment depuis l'interface (**Vérifier l'intégrité**) ou en
ligne de commande : `cd <sauvegarde> && sha256sum -c SHA256SUMS`.

**Non sauvegardable via ADB sans root** : données privées des applications,
SMS, journal d'appels, contacts (exportez vos contacts en .vcf dans
Téléchargements pour les inclure). Le logiciel ne prétend pas le faire.

## Avertissements

- Ce logiciel ne contourne **aucun** mécanisme de sécurité (bootloader, Verified
  Boot, FRP, verrouillage opérateur, antivol).
- GrapheneOS n'est **pas** redistribué : il sera téléchargé exclusivement depuis
  les serveurs officiels et vérifié avant toute utilisation.
- Le déverrouillage du bootloader et le flashage effacent toutes les données du
  téléphone. Ces opérations exigeront toujours une confirmation explicite.
- GrapheneOS est une marque de la GrapheneOS Foundation ; ce projet n'y est pas affilié.

## Dépannage

**`adb introuvable` / `fastboot introuvable`** — installez les Platform Tools
(section ci-dessus) et renseignez `LMS_PLATFORM_TOOLS_DIR`.

**Fastboot en « Attention » (version < 35.0.1)** — votre fastboot vient
probablement d'un paquet de distribution ; utilisez la version standalone officielle.

**Linux : règles udev manquantes** — sans elles, fastboot ne voit le Pixel qu'en root.
Arch : `sudo pacman -S android-udev` ; Debian/Ubuntu : `sudo apt install android-sdk-platform-tools-common`.

**Linux : fwupd en cours d'exécution** — il peut interrompre le mode fastboot
pendant le flashage : `sudo systemctl stop fwupd.service` avant l'installation.

**Windows : téléphone non détecté en fastboot** — installez le « Google USB Driver »
(Windows Update › mises à jour facultatives).

**Appareil « Non autorisé »** — déverrouillez l'écran et acceptez la fenêtre
« Autoriser le débogage USB ? ». Sinon, révoquez les autorisations dans les
Options pour les développeurs puis rebranchez.

**Appareil « Hors ligne »** — rebranchez le câble, puis « Redémarrer le serveur ADB »
dans la page Appareils. Essayez un autre câble (certains ne transportent que le courant).

**`le port 8765 est déjà utilisé`** — une instance tourne déjà, ou utilisez `--port`.

**« Requête refusée »** dans l'interface — rechargez la page (le jeton de
session change à chaque lancement).

## Tests et développement

```bash
./install.sh --dev
.venv/bin/python -m pytest          # aucun téléphone requis
.venv/bin/ruff check . && .venv/bin/ruff format --check .
```

Les tests installent de **faux `adb`/`fastboot` exécutables**
(`tests/fakes/fake_platform_tool.py`) pour exercer le vrai chemin `subprocess`
(timeouts, échecs, versions obsolètes, sorties inattendues) sans matériel.
Les téléphones « branchés » sont décrits par la fixture `fake_devices`
(Pixel 8 Pro verrouillé ou déverrouillé, Samsung ancien, appareil minimal ;
états unauthorized, offline, no permissions, fastboot…) avec des sorties
reproduisant celles des vrais outils (`tests/fakes/profiles.py`).
Ces tests utilisent un shebang POSIX et sont ignorés sous Windows.

Ajouter une commande ADB/Fastboot = ajouter une entrée à `COMMAND_WHITELIST`
dans `app/core/platform_tools.py` (gabarit fixe + `Arg` validés) et un test.

## Sécurité

Résumé du modèle de menace : [docs/SECURITY.md](docs/SECURITY.md) — serveur
limité au loopback, protection DNS rebinding et CSRF, CSP stricte, liste blanche
de commandes sans shell, masquage des secrets, audit chaîné.

## Licence

MIT — voir [LICENSE](LICENSE).
