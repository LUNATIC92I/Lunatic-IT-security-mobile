# LUNATIC MOBILE SECURITY

Logiciel de bureau pour **auditer et renforcer la sécurité d'un smartphone
Android** et **installer GrapheneOS sur un Google Pixel compatible** en suivant
exclusivement la procédure officielle. Backend Python (FastAPI), interface
HTML/CSS/JavaScript ouverte dans le navigateur, tout fonctionne en local.

> **Version 0.1.0.** Toutes les fonctions décrites ici sont implémentées et
> testées (374 tests automatisés, voir [docs/TESTING.md](docs/TESTING.md)).
> L'assistant d'installation GrapheneOS a été validé avec les vrais outils
> officiels, les vraies images signées et le vrai script `flash-all.sh`, mais
> contre un **Pixel simulé** : lisez la section [Avertissements](#avertissements)
> avant de l'utiliser sur un vrai téléphone.

## Sommaire

1. [Présentation](#présentation)
2. [Architecture](#architecture)
3. [Prérequis](#prérequis)
4. [Installation](#installation)
5. [Installation Android Platform Tools](#installation-android-platform-tools)
6. [Lancement](#lancement)
7. [Configuration](#configuration)
8. [Utilisation](#utilisation)
9. [Security Scan](#security-scan)
10. [Renforcement](#renforcement)
11. [Backup](#backup)
12. [GrapheneOS](#grapheneos)
13. [Avertissements](#avertissements)
14. [Dépannage](#dépannage)
15. [Tests](#tests)
16. [Développement](#développement)
17. [Sécurité](#sécurité)
18. [Licence](#licence)

---

## Présentation

### À quoi sert le logiciel

| Besoin | Ce que fait LUNATIC MOBILE SECURITY |
|--------|--------------------------------------|
| Savoir si un téléphone Android est bien protégé | **Security Scan** : audit en lecture seule (système, démarrage sécurisé, applications, permissions, réseau, chiffrement, mises à jour), score de 0 à 100, recommandations expliquées avec preuve technique. |
| Corriger les points faibles | **Renforcement** : corrections une par une, chacune présentée **[AVANT] / [APRÈS] / [RISQUE]**, confirmée, appliquée puis **vérifiée par relecture** sur le téléphone. |
| Mettre ses fichiers à l'abri | **Backup** : copie du stockage partagé (photos, documents…) et des APK, chaque fichier contrôlé par SHA-256 sur le téléphone **et** sur l'ordinateur. |
| Passer à GrapheneOS | **GrapheneOS** : compatibilité, téléchargement depuis les serveurs officiels, vérification cryptographique de la signature, puis **assistant d'installation en 13 étapes** qui exécute le script officiel. |

### Principes

- **Rien n'est simulé** : une fonction absente n'apparaît pas dans l'interface ;
  ce qu'Android ne permet pas de lire est signalé comme « limite », jamais deviné.
- **Rien n'est présumé réussi** : une opération n'est annoncée réussie
  qu'après une relecture qui le prouve.
- **Rien de destructif sans confirmation** : déverrouillage, effacement,
  flashage et verrouillage exigent une confirmation explicite, contrôlée côté
  serveur (pas seulement par un bouton).
- **Aucun contournement** de sécurité : bootloader, Verified Boot, FRP,
  verrouillage opérateur, antivol et protections Google sont respectés.
- **Confidentialité** : tout reste sur l'ordinateur ; les numéros de série
  sont masqués (`HU•••••••••01`), aucun mot de passe ni secret n'est enregistré.
- **Erreurs compréhensibles** : chaque problème est affiché sous la forme
  **ERREUR / CAUSE POSSIBLE / ACTION**.

### Ce que le logiciel ne fait pas

Ce n'est pas un antivirus (il ne lit pas le contenu des applications), il
n'utilise pas le root, ne déverrouille pas un téléphone verrouillé par un
opérateur ou par un compte Google (FRP), et ne sauvegarde pas les données
qu'Android réserve aux applications (conversations, SMS, comptes).

---

## Architecture

```
  Navigateur  ── http://127.0.0.1:8765 ──►  Serveur FastAPI (cet ordinateur uniquement)
  interface HTML/CSS/JS                      │  contrôles : Host, jeton CSRF, Origin, CSP
  (logs en direct par SSE)                   │
                                             ├─ core/      appareils, scan, sauvegarde, audit
                                             ├─ security/  analyseurs, score, renforcement
                                             ├─ graphene/  compatibilité, téléchargement,
                                             │             signature, assistant d'installation
                                             │
                                             ├─ CommandRunner (liste blanche, jamais de shell)
                                             │      │
                                             │      ▼
                                             │  adb / fastboot (Platform Tools officielles)
                                             │      │ USB
                                             │      ▼
                                             │  Téléphone : Android (ADB) ou bootloader (Fastboot)
                                             │
                                             └─ HTTPS (TLS vérifié, sans redirection)
                                                    ▼
                                                releases.grapheneos.org
```

```
app/
  main.py                point d'entrée : serveur FastAPI, middlewares, CLI (--check, --port…)
  config.py              paramètres LMS_* validés (loopback, source officielle HTTPS)
  logging_config.py      logs masqués, tampon mémoire, identifiant de lancement
  api/                   routes HTTP : système, appareils, sécurité, renforcement, backup, GrapheneOS
  core/
    platform_tools.py    liste blanche des commandes adb/fastboot, exécution, timeouts, annulation
    device_manager.py    détection ADB/Fastboot, états, identifiants opaques, sélection
    adb_manager.py       lecture des propriétés (liste blanche), stockage, batterie
    fastboot_manager.py  lecture des variables du bootloader
    security_scanner.py  analyse en tâche de fond, rapports
    hardening_service.py renforcement (une modification à la fois)
    backup_manager.py    sauvegarde vérifiée SHA-256
    grapheneos_manager.py façade GrapheneOS
    environment.py       diagnostic de l'ordinateur
    storage.py           occupation disque, nettoyage du dossier temporaire
    audit_logger.py      journal d'audit chaîné SHA-256
    errors.py, safety.py erreurs ERREUR/CAUSE/ACTION, validation, masquage, chemins
  security/              collecte Android, analyseurs, score, actions de renforcement
  graphene/              catalogue, métadonnées officielles, téléchargement, vérification SSHSIG,
                         assistant d'installation
  models/                modèles Pydantic échangés par l'API
frontend/                index.html, css/, js/ (une vue par page, aucun framework)
tests/                   pytest + faux adb/fastboot exécutables + faux serveur GrapheneOS
docs/                    ARCHITECTURE, SECURITY, TESTING, PACKAGING, ROADMAP
install.sh, scripts/install.ps1   installation Linux/macOS et Windows (option raccourci)
scripts/build_release.sh contrôles + construction du wheel et des sources + SHA256SUMS
pyproject.toml           métadonnées du paquet, commande lunatic-mobile-security
```

Détails techniques (score, protocole de vérification, machine à états de
l'installation, flux de logs) : [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Prérequis

| | Linux | macOS | Windows |
|---|---|---|---|
| Python | 3.10 ou plus (`python3-venv` sous Debian/Ubuntu) | 3.10 ou plus | 3.10 ou plus (python.org, cocher « Add python.exe to PATH ») |
| Platform Tools | standalone officiel (ou `android-tools` d'Arch) | standalone officiel | standalone officiel |
| Accès USB | règles udev pour les appareils Google | rien | pilote « Google USB Driver » |
| Flashage GrapheneOS | `bash` (présent par défaut) | `bash` (présent par défaut) | `cmd.exe` (présent par défaut) |
| Navigateur | Firefox, Chromium, Chrome, Edge, Safari récents | | |

Matériel et espace :

- un **câble USB de données** branché **directement** sur l'ordinateur (pas de hub) ;
- pour GrapheneOS : un Pixel pris en charge (liste dans [GrapheneOS](#grapheneos)),
  **acheté débloqué** (les variantes opérateur ne peuvent pas déverrouiller
  leur bootloader), environ **32 Go libres** (image + extraction) ;
- pour une sauvegarde : l'espace correspondant aux dossiers choisis
  (affiché avant de commencer).

Le système d'exploitation est détecté automatiquement.

---

## Installation

### Linux / macOS

```bash
git clone https://github.com/LUNATIC92I/Lunatic-IT-security-mobile.git
cd Lunatic-IT-security-mobile
./install.sh            # ou : ./install.sh --dev  (ajoute pytest, ruff…)
```

Le script vérifie Python, crée l'environnement virtuel `.venv`, installe les
dépendances et lance le diagnostic. Il n'installe rien en dehors du dossier et
ne demande pas les droits administrateur.

### Windows (PowerShell)

```powershell
git clone https://github.com/LUNATIC92I/Lunatic-IT-security-mobile.git
cd Lunatic-IT-security-mobile
powershell -ExecutionPolicy Bypass -File scripts\install.ps1
```

Option `--shortcut` (Windows : `-Shortcut`) : crée un raccourci de lancement
dans le menu Applications (Linux), `~/Applications` (macOS) ou le menu Démarrer
(Windows).

### Installation par paquet (pipx)

Si vous disposez du paquet `lunatic_mobile_security-<version>-py3-none-any.whl`
(construit par `scripts/build_release.sh`, voir [Développement](#développement)) :

```bash
sha256sum -c SHA256SUMS                     # vérifier l'empreinte du paquet
pipx install ./lunatic_mobile_security-0.1.0-py3-none-any.whl
lunatic-mobile-security --check
lunatic-mobile-security
```

pipx installe le logiciel dans son propre environnement isolé et ajoute la
commande `lunatic-mobile-security`. Détails par système (Linux, macOS,
Windows), configuration et désinstallation : [docs/PACKAGING.md](docs/PACKAGING.md).

### Installation manuelle

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt          # Windows : .venv\Scripts\pip
```

### Mise à jour et désinstallation

- Mise à jour : `git pull` puis relancer `./install.sh` (ou `install.ps1`) ;
  paquet : `pipx install --force <nouveau paquet>`.
- Désinstallation : supprimer le dossier du projet (paquet :
  `pipx uninstall lunatic-mobile-security`), puis, si vous le souhaitez,
  le répertoire de données (voir [Configuration](#configuration)), qui
  contient logs, rapports, images téléchargées et, par défaut, les sauvegardes.
  **Vérifiez d'avoir copié vos sauvegardes ailleurs avant de le supprimer.**

---

## Installation Android Platform Tools

Le logiciel pilote les outils officiels de Google `adb` et `fastboot`. Il ne
les télécharge pas lui-même : installez la version **standalone officielle**.
Les paquets Debian/Ubuntu sont trop anciens pour GrapheneOS, qui exige
**fastboot 35.0.1 ou plus**. Commandes et empreintes reprises du
[guide officiel GrapheneOS](https://grapheneos.org/install/cli#standalone-platform-tools) :

```bash
# Linux
curl -O https://dl.google.com/android/repository/platform-tools_r35.0.2-linux.zip
echo 'acfdcccb123a8718c46c46c059b2f621140194e5ec1ac9d81715be3d6ab6cd0a  platform-tools_r35.0.2-linux.zip' | sha256sum -c
bsdtar xvf platform-tools_r35.0.2-linux.zip      # ou : unzip

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

N'extrayez l'archive que si la vérification affiche `OK` (ou `True`). Sous
Arch Linux, le paquet `android-tools` est à jour et convient aussi.

Indiquez ensuite où se trouvent les outils, au choix (ordre de recherche du logiciel) :

1. variable `LMS_PLATFORM_TOOLS_DIR=/chemin/vers/platform-tools` (ou ligne dans `.env`) ;
2. copie du dossier dans `<répertoire de données>/platform-tools` ;
3. ajout du dossier au `PATH`.

Contrôle : `.venv/bin/python -m app.main --check` doit afficher ADB et
Fastboot `35.0.2-…` avec `[✓]`. La page **Paramètres** affiche aussi le chemin
et la version détectés.

**Accès USB sous Linux** : sans règles udev, `fastboot` ne voit le Pixel qu'en
root. Arch : `sudo pacman -S android-udev` ; Debian/Ubuntu :
`sudo apt install android-sdk-platform-tools-common` (ce paquet ne fournit que
les règles udev). Débranchez puis rebranchez le téléphone ensuite.

**Pilote USB sous Windows** : le mode Fastboot nécessite le « Google USB
Driver », installé en général par Windows Update (Paramètres › Windows Update ›
Options avancées › Mises à jour facultatives).

---

## Lancement

```bash
.venv/bin/python -m app.main               # démarre et ouvre l'interface dans le navigateur
.venv/bin/python -m app.main --no-browser  # serveur seul, puis ouvrir http://127.0.0.1:8765/
.venv/bin/python -m app.main --port 9000   # autre port
.venv/bin/python -m app.main --check       # diagnostic texte (code retour 1 si un prérequis manque)
.venv/bin/python -m app.main --check --json
```

Windows : remplacez `.venv/bin/python` par `.venv\Scripts\python`.

Exemple de diagnostic :

```
LUNATIC MOBILE SECURITY 0.1.0 — diagnostic de l'environnement
Système : Linux 6.8.0 (x86_64), Python 3.12.3
  [✓] Python: Python 3.12.3
  [✓] Répertoire de données: /home/alice/.local/share/lunatic-mobile-security
  [✓] Espace disque: 120.4 Go libres
  [✓] ADB: 35.0.2-12147458 — /home/alice/platform-tools/adb
  [✓] Fastboot: 35.0.2-12147458 — /home/alice/platform-tools/fastboot
  [✓] Règles udev (USB Pixel): Règle Google trouvée : /usr/lib/udev/rules.d/51-android.rules
  [✓] Service fwupd: fwupd n'est pas en cours d'exécution.
Résultat global : OK
```

Arrêt : `Ctrl+C` dans le terminal. L'arrêt est inscrit au journal d'audit.
Un flashage en cours ne doit **jamais** être interrompu ainsi.

L'interface n'est accessible que depuis l'ordinateur lui-même (adresse
`127.0.0.1`). Un jeton de session est créé à chaque lancement : après un
redémarrage du logiciel, rechargez la page.

---

## Configuration

Variables d'environnement `LMS_*` ou fichier `.env` (modèle commenté :
[.env.example](.env.example)) placé à la racine du projet ou, pour une
installation par paquet, dans le répertoire de données (`<répertoire de
données>/.env`). Priorité : variables d'environnement, puis `.env` du projet,
puis `.env` du répertoire de données. Les valeurs sont contrôlées
au démarrage ; une valeur dangereuse est refusée avec un message explicite.

| Variable | Défaut | Remarque |
|----------|--------|----------|
| `LMS_HOST` | `127.0.0.1` | adresse de bouclage uniquement (`127.0.0.1`, `::1`, `localhost`) ; toute autre valeur est refusée |
| `LMS_PORT` | `8765` | 1024 à 65535 |
| `LMS_DATA_DIR` | voir ci-dessous | logs, rapports, images, sauvegardes, fichiers temporaires |
| `LMS_PLATFORM_TOOLS_DIR` | — | dossier contenant `adb` et `fastboot` |
| `LMS_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARN`, `ERROR`, `CRITICAL` |
| `LMS_COMMAND_TIMEOUT` | `30` | délai maximal d'une commande, en secondes (1 à 600) |
| `LMS_FLASH_TIMEOUT` | `1800` | délai maximal du flashage, en secondes (60 à 7200) |
| `LMS_OPEN_BROWSER` | `true` | ouvrir le navigateur au démarrage |
| `LMS_GRAPHENEOS_RELEASES_URL` | `https://releases.grapheneos.org` | HTTPS et hôte officiel GrapheneOS obligatoires |

Répertoire de données par défaut :

| Système | Chemin |
|---------|--------|
| Linux | `~/.local/share/lunatic-mobile-security` (ou `$XDG_DATA_HOME/lunatic-mobile-security`) |
| macOS | `~/Library/Application Support/LunaticMobileSecurity` |
| Windows | `%LOCALAPPDATA%\LunaticMobileSecurity` |

Contenu : `logs/lunatic.log` (rotation 5 × 5 Mo), `logs/audit.jsonl` (journal
d'audit), `reports/` (rapports d'analyse JSON), `downloads/` (images GrapheneOS
vérifiées), `backups/` (destination de sauvegarde par défaut), `tmp/`
(extraction pendant le flashage, vidée automatiquement), `platform-tools/`
(emplacement optionnel des outils). Sous Linux et macOS, ces dossiers sont
créés avec des droits réservés à votre compte (`0700`).

---

## Utilisation

### Préparer le téléphone (une seule fois)

1. **Paramètres › À propos du téléphone** : touchez 7 fois **Numéro de build**
   pour afficher les options pour les développeurs.
2. **Paramètres › Système › Options pour les développeurs** : activez
   **Débogage USB**.
3. Branchez le téléphone, déverrouillez l'écran et acceptez **« Autoriser le
   débogage USB ? »** (cochez « Toujours autoriser » sur votre propre ordinateur).

L'appareil apparaît alors dans **Appareils** avec le badge « ADB ». S'il est
« Non autorisé » ou « Hors ligne », la page indique quoi faire.

### Pages de l'interface

| Page | Contenu | Modifie le téléphone ? |
|------|---------|------------------------|
| **Dashboard** | Diagnostic de l'ordinateur (Python, disque, adb, fastboot, udev, fwupd), appareil connecté, dernier score de sécurité. | Non |
| **Appareils** | Appareils ADB et Fastboot (actualisation automatique), sélection de l'appareil cible quand il y en a plusieurs, fiche détaillée : modèle, codename, Android, patch de sécurité et son âge, bootloader, Verified Boot, chiffrement, stockage, batterie. Bouton « Redémarrer le serveur ADB » (confirmation). | Non |
| **Security Scan** | Lancement de l'analyse, score, notes par catégorie, recommandations triées par gravité, limites de l'analyse. | Non |
| **Renforcement** | Corrections proposées d'après l'état réel du téléphone, une par une, avec confirmation et vérification. | **Oui**, après confirmation |
| **Applications** | Applications installées par l'utilisateur : origine (Play Store, autre magasin, installation manuelle), date, permissions sensibles, score de risque contextuel. | Non |
| **Permissions** | Permissions sensibles par groupe (caméra, micro, localisation, SMS, contacts…) et accès spéciaux (accessibilité, notifications, administrateur, installation d'applications, VPN). | Non |
| **Réseau** | Wi-Fi (sécurité du réseau, sans SSID ni adresse enregistrés), DNS privé, proxy, VPN, ADB sans fil. | Non |
| **Chiffrement** | Type et état du chiffrement du stockage. | Non |
| **Bootloader** | Verrouillage du bootloader, état Verified Boot, signification de chaque couleur (green, yellow, orange). | Non |
| **Mises à jour** | Version Android, patch de sécurité et son ancienneté, fin de support. | Non |
| **Backup** | Sauvegarde vérifiée du stockage partagé et des APK, liste et revérification des sauvegardes. | Non (lecture seule) |
| **GrapheneOS** | Compatibilité, version officielle, téléchargement et vérification, images enregistrées, appareils pris en charge. | Non |
| **Installation** | Assistant en 13 étapes. | **Oui (efface tout)**, après confirmations |
| **Logs** | Journal en temps réel (filtre par niveau et par texte, pause, export `.txt`). | Non |
| **Paramètres** | Configuration effective, outils détectés, occupation disque, nettoyage des fichiers temporaires, garanties de sécurité, journal d'audit et vérification de son intégrité. | Non |

L'interface s'utilise entièrement au clavier (lien « Aller au contenu »,
focus visible, Échap ferme les fenêtres et le menu mobile) et s'adapte aux
petits écrans.

### Lire une erreur

```
ERREUR          L'appareil n'est pas autorisé.
CAUSE POSSIBLE  Le téléphone n'a pas encore accepté cet ordinateur.
ACTION          Déverrouillez l'écran et acceptez « Autoriser le débogage USB ? ».
```

Le détail technique éventuel (sortie d'adb/fastboot, numéros de série masqués)
est disponible sous le message et dans la page **Logs**.

---

## Security Scan

1. Branchez le téléphone (débogage USB autorisé) et ouvrez **Security Scan**.
2. Cliquez sur **Lancer l'analyse**. La progression s'affiche étape par étape :
   quelques secondes, jusqu'à une minute avec plusieurs centaines d'applications.
3. Lisez les recommandations, les plus graves en premier. Chaque carte indique
   le **problème**, la **gravité**, **pourquoi c'est important**, la **preuve
   technique** (commande et valeur lue), la **recommandation** et la
   **méthode de correction**. Quand une correction automatique existe, un
   lien mène au Renforcement.

L'analyse **ne modifie rien**. Le rapport est conservé pendant la session et
enregistré en JSON dans `reports/`, sans numéro de série.

### Ce qui est analysé

| Catégorie | Constats possibles |
|-----------|--------------------|
| Système | débogage USB actif, options pour les développeurs actives, vérification des applications installées par ADB désactivée, sources inconnues (Android < 8) |
| Démarrage sécurisé | Verified Boot `red`/`orange`, bootloader déverrouillé, déverrouillage OEM autorisé, clé de démarrage personnalisée, SELinux non appliqué, binaire `su` (root), build de débogage, build signé avec `test-keys` |
| Applications | applications installées hors magasin d'applications, installations récentes, score de risque contextuel par application (origine × permissions × accès spéciaux) |
| Permissions | services d'accessibilité, accès aux notifications, administrateurs de l'appareil, propriétaire MDM, droit d'installer des applications, accès aux SMS, localisation en arrière-plan, applications cumulant de nombreuses permissions sensibles |
| Réseau | proxy global, Wi-Fi ouvert ou faiblement protégé, DNS privé désactivé, ADB sans fil actif (VPN affiché à titre d'information) |
| Chiffrement | stockage non chiffré, ancien chiffrement intégral (FDE), état indéterminé |
| Mises à jour | patch de sécurité ancien ou inconnu, version d'Android plus maintenue |

### Calcul du score

Score = 100 − pénalités. Chaque constat retire des points selon sa gravité :
**critique 35, élevée 15, moyenne 6, faible 2**, information 0. La pénalité de
chaque catégorie est plafonnée (beaucoup de petits constats identiques ne
suffisent pas à atteindre zéro). Un constat **critique** limite le score à
**39**, un constat de gravité **élevée** à **74** : une faiblesse grave reste
visible dans la note.

| Score | Note |
|-------|------|
| 90 à 100 | Excellent |
| 75 à 89 | Bon |
| 60 à 74 | Moyen |
| 40 à 59 | Faible |
| 0 à 39 | Critique |

### Limites de l'analyse

ADB sans root ne permet pas de vérifier : la présence et la robustesse du code
de verrouillage, les certificats installés par l'utilisateur, les comptes
(seuls leurs **types** sont lus), une mise à jour en attente, l'attestation
matérielle, le contenu des applications. Ces points sont listés dans le
rapport comme « limites » et dans les vérifications manuelles du Renforcement.

---

## Renforcement

La page **Renforcement** lit l'état actuel du téléphone et ne propose que les
corrections réellement applicables :

| Correction | Effet |
|------------|-------|
| Désactiver un service d'accessibilité | retire un service capable de lire l'écran et d'agir à votre place |
| Retirer le droit d'installer des applications | pour une application qui n'en a pas besoin (sources inconnues) |
| Révoquer une permission sensible | caméra, micro, localisation, SMS… pour une application précise |
| Supprimer le proxy global | le trafic ne passe plus par un intermédiaire configuré à votre insu |
| Activer le DNS privé | DNS chiffré en mode automatique |
| Désactiver ADB sans fil | ferme l'accès de débogage par le réseau |
| Réactiver la vérification des installations USB | les APK installés par câble sont de nouveau contrôlés |
| Désactiver le débogage USB | proposé **toujours en dernier** : le logiciel perd ensuite l'accès au téléphone |

Pour chaque correction : fenêtre **[AVANT] / [APRÈS] / [RISQUE] /
[CONFIRMATION]**, application seule, puis **relecture** du réglage sur le
téléphone. Le résultat affiché (« Vérifié » ou l'écart constaté) provient de
cette relecture. Le plan est signé et valable 15 minutes : si le téléphone a
changé entre-temps, la correction est refusée et le plan doit être relu.

Non automatisé (aucun mécanisme ADB fiable sans root, ou risque de perte de
données) : retrait d'un administrateur de l'appareil, désinstallation
d'applications, accès aux notifications, code de verrouillage. Ces points
figurent dans la liste des **vérifications manuelles** avec le chemin exact
dans les Paramètres d'Android.

---

## Backup

1. Ouvrez **Backup** : la taille de chaque dossier du stockage partagé s'affiche.
2. Cochez les dossiers (DCIM, Pictures, Movies, Music, Documents, Download, Recordings…)
   et, si besoin, les **APK des applications tierces** (pour les réinstaller).
3. Choisissez la destination (**Parcourir…**, par défaut `backups/` du
   répertoire de données). L'espace libre est contrôlé avant de commencer.
4. **Démarrer** : progression, nombre de fichiers vérifiés, annulation
   possible. Une sauvegarde annulée ou en échec est supprimée : il ne reste
   jamais de copie partielle présentée comme valable.
5. Résultat : **« SHA-256 vérifié »** uniquement si chaque fichier copié est
   identique à l'original (empreinte calculée sur le téléphone puis sur
   l'ordinateur). Sinon, la liste précise des anomalies est affichée (fichier
   différent, manquant, modifié pendant la sauvegarde).

Chaque sauvegarde contient `SHA256SUMS` et `backup.json` (sans numéro de
série). Revérification à tout moment depuis l'interface (**Vérifier
l'intégrité**) ou avec l'outil standard :

```bash
cd <dossier de la sauvegarde> && sha256sum -c SHA256SUMS
```

**Non sauvegardable via ADB sans root**, et le logiciel ne prétend pas le
faire : données privées des applications (conversations, réglages), SMS,
journal d'appels, contacts (exportez-les en `.vcf` dans Téléchargements pour
les inclure), le dossier `Android/data`. Utilisez la sauvegarde propre à
chaque application ou celle du système pour ces données.

---

## GrapheneOS

GrapheneOS est un système Android renforcé pour les Google Pixel. Le logiciel
suit la **procédure officielle en ligne de commande**
([grapheneos.org/install/cli](https://grapheneos.org/install/cli)). Le
[programme d'installation web officiel](https://grapheneos.org/install/web)
reste une alternative tout aussi valable.

### 1. Compatibilité

La page **GrapheneOS** vérifie, pour le téléphone connecté (en Android ou en
mode Fastboot) :

- modèle pris en charge et durée de support restante ;
- version officielle publiée sur le canal choisi (Stable, Beta, Alpha), lue en
  direct sur `releases.grapheneos.org` ;
- possibilité de déverrouiller le bootloader (« Déverrouillage OEM » ou
  `get_unlock_ability`). Une variante opérateur verrouillée **ne peut pas**
  recevoir GrapheneOS : le logiciel ne contourne pas ce verrouillage ;
- version de fastboot (35.0.1 minimum), espace disque (32 Go).

Appareils pris en charge (catalogue du 6 octobre 2026, fin de support
constructeur) :

| Modèle | Codename | Support jusqu'à | | Modèle | Codename | Support jusqu'à |
|---|---|---|---|---|---|---|
| Pixel 10a | stallion | 2033-03 | | Pixel 8a | akita | 2031-05 |
| Pixel 10 Pro Fold | rango | 2032-10 | | Pixel 8 Pro | husky | 2030-10 |
| Pixel 10 Pro XL | mustang | 2032-08 | | Pixel 8 | shiba | 2030-10 |
| Pixel 10 Pro | blazer | 2032-08 | | Pixel Fold | felix | 2028-06 |
| Pixel 10 | frankel | 2032-08 | | Pixel Tablet | tangorpro | 2028-06 |
| Pixel 9a | tegu | 2032-04 | | Pixel 7a | lynx | 2028-05 |
| Pixel 9 Pro Fold | comet | 2031-08 | | Pixel 7 Pro | cheetah | 2027-10 |
| Pixel 9 Pro XL | komodo | 2031-08 | | Pixel 7 | panther | 2027-10 |
| Pixel 9 Pro | caiman | 2031-08 | | Pixel 6a | bluejay | 2027-07 |
| Pixel 9 | tokay | 2031-08 | | Pixel 6 Pro | raven | 2026-10 |
| | | | | Pixel 6 | oriole | 2026-10 |

La version disponible pour chaque appareil vient toujours du serveur officiel :
un appareil absent du serveur n'est pas proposé.

### 2. Téléchargement et vérification

**Télécharger et vérifier** récupère l'image d'installation officielle
(`<codename>-install-<version>.zip`), sa signature et la clé publique depuis
`releases.grapheneos.org`, en HTTPS avec vérification TLS et sans suivre de
redirection. Une coupure réseau n'oblige pas à tout recommencer : relancez, le
téléchargement **reprend où il s'était arrêté**.

Vérifications, toutes obligatoires :

1. **signature** : même contrôle que `ssh-keygen -Y verify` du guide officiel
   (signature SSH Ed25519, espace de noms `factory images`), avec la clé
   publique GrapheneOS **épinglée dans le logiciel**
   (empreinte `SHA256:AhgHif0mei+9aNyKLfMZBh2yptHdw/aN7Tlh/j2eFwM`) ;
2. **empreintes** SHA-256 et SHA-512 et taille annoncée ;
3. **contenu de l'archive** : bon appareil, bonne version, aucun chemin
   dangereux, clé Verified Boot (`avb_pkmd.bin`) identique à l'empreinte
   officielle de l'appareil.

Étapes affichées : **Download → Verification → Ready**. En cas d'échec :
**« Verification FAILED — Installation blocked »**, le fichier est supprimé et
ne peut pas être flashé. Les images vérifiées peuvent être revérifiées ou
supprimées depuis la même page ; l'image est de nouveau contrôlée juste avant
le flashage.

### 3. Installation guidée (page « Installation »)

| # | Étape | Ce que fait le logiciel | Ce que vous faites |
|---|-------|------------------------|--------------------|
| 1 | Connecter le Pixel | détecte le téléphone (un seul) | branchez-le, débogage USB autorisé |
| 2 | Détecter le modèle | lit le codename | — |
| 3 | Compatibilité | contrôles du §1 | — |
| 4 | Avertissement | affiche **« Cette opération peut effacer toutes les données du téléphone. »** | lisez |
| 5 | Confirmation explicite | exige la phrase `EFFACER <CODENAME>` et deux cases (perte des données, sauvegarde faite) | tapez la phrase |
| 6 | Vérifier ADB / Fastboot | versions des outils | — |
| 7 | Préparer l'appareil | redémarre en mode Fastboot puis demande le déverrouillage du bootloader (**efface le téléphone**, confirmation) | activez « Déverrouillage OEM » dans Android, puis validez le déverrouillage **sur le téléphone** avec les touches de volume |
| 8 | Composants officiels | utilise l'image vérifiée du §2 | — |
| 9 | Vérification d'intégrité | recontrôle signature et empreintes | — |
| — | Contrôles préalables | un seul appareil, mode Fastboot, bon modèle, bootloader déverrouillé, batterie, image, signature, fastboot, script, espace disque, droits d'écriture, confirmation → **READY TO INSTALL** (valable 15 min, une seule fois) | — |
| 10 | Flashage | extrait l'image vérifiée et exécute **le script officiel `flash-all`** qu'elle contient ; sortie Fastboot complète en direct (confirmation) | ne touchez à rien, ne débranchez pas |
| 11 | Vérifier et verrouiller | relit les variables du bootloader, puis verrouille (**efface de nouveau**, confirmation) | validez le verrouillage **sur le téléphone** |
| 12 | Configuration finale | redémarre le téléphone | suivez l'assistant de GrapheneOS ; au dernier écran, laissez cochée la désactivation du déverrouillage OEM |
| 13 | Vérification de sécurité | relit Verified Boot (`yellow` attendu avec GrapheneOS), verrouillage, modèle et **version installée** | optionnel : réactivez temporairement le débogage USB pour cette vérification |

Le logiciel **refuse** : de passer une étape sans avoir réussi la précédente ;
de flasher si un contrôle préalable échoue (deuxième appareil branché, image
modifiée, batterie non confirmée…) ; de verrouiller le bootloader si le
flashage n'a pas réussi (cela rendrait le téléphone inutilisable) ;
d'interrompre ou d'abandonner un flashage en cours.

**Si le flashage échoue** (câble débranché, téléphone qui refuse une
écriture, délai dépassé) : la sortie Fastboot complète reste affichée avec une
explication en clair. **Ne verrouillez pas** le bootloader, ne redémarrez pas
le téléphone : rebranchez-le (port USB direct), revenez en mode Fastboot si
nécessaire, relancez les contrôles préalables puis le flashage.

**Après l'installation** : à chaque démarrage, un écran jaune signale un
système d'exploitation différent ; c'est normal avec GrapheneOS (Verified Boot
`yellow`). Comparez l'empreinte de clé affichée avec l'empreinte officielle de
votre modèle (indiquée par l'assistant) et utilisez l'application **Auditor**
pour une vérification matérielle. Désactivez le débogage USB et les options
développeur si vous les avez réactivés pour l'étape 13.

---

## Avertissements

- **Le déverrouillage du bootloader, le flashage et le verrouillage effacent
  toutes les données du téléphone**, définitivement. Faites une sauvegarde
  avant (page **Backup**) et vérifiez-la.
- L'assistant d'installation a été testé avec les vrais `adb`/`fastboot`
  35.0.2, de vraies images GrapheneOS signées et le vrai script officiel, mais
  **contre un Pixel simulé**. Sur un vrai téléphone, suivez en parallèle le
  guide officiel `grapheneos.org/install/cli` ; en cas de doute, utilisez le
  programme d'installation web officiel.
- Ce logiciel ne contourne **aucun** mécanisme de sécurité : bootloader,
  Verified Boot, FRP (protection contre la réinitialisation), verrouillage
  opérateur, antivol, protections Google.
- GrapheneOS n'est **pas** redistribué : chaque image est téléchargée depuis
  les serveurs officiels et vérifiée avant usage.
- Le Security Scan n'est pas un antivirus : un bon score signifie une bonne
  configuration, pas l'absence de logiciel malveillant.
- N'interrompez jamais un flashage (pas de `Ctrl+C`, pas de débranchement,
  pas de mise en veille de l'ordinateur).
- GrapheneOS est une marque de la GrapheneOS Foundation ; Google, Pixel et
  Android sont des marques de Google LLC. Ce projet n'est affilié à aucune
  d'elles.

---

## Dépannage

### Outils et ordinateur

| Symptôme | Solution |
|----------|----------|
| `adb introuvable` / `fastboot introuvable` | Installez les Platform Tools ([section dédiée](#installation-android-platform-tools)) et renseignez `LMS_PLATFORM_TOOLS_DIR`. Vérifiez avec `--check`. |
| Fastboot en « Attention », version inférieure à 35.0.1 | Il provient sans doute d'un paquet de distribution : utilisez la version standalone officielle et placez-la en premier (`LMS_PLATFORM_TOOLS_DIR`). |
| `le port 8765 est déjà utilisé` | Une instance tourne déjà (ouvrez `http://127.0.0.1:8765/`) ou lancez avec `--port 9000`. |
| « Requête refusée » dans l'interface | Le logiciel a redémarré : rechargez la page (nouveau jeton de session). |
| Logs : badge « Serveur injoignable » | Le serveur est arrêté ; relancez-le, la page se reconnecte seule et affiche « Application redémarrée ». |
| « Impossible d'écrire dans le dossier de données » | Vérifiez l'espace disque et les droits du dossier indiqué, ou choisissez-en un autre avec `LMS_DATA_DIR`. |
| Espace disque insuffisant pour GrapheneOS | Libérez environ 32 Go, ou supprimez d'anciennes images (page GrapheneOS) et videz les fichiers temporaires (Paramètres). |

### Connexion du téléphone

| Symptôme | Solution |
|----------|----------|
| Aucun appareil détecté | Câble de données (certains ne font que charger), port USB direct, écran déverrouillé, débogage USB activé. Sous Linux, vérifiez les règles udev. |
| « Non autorisé » | Déverrouillez l'écran et acceptez « Autoriser le débogage USB ? ». Sinon : Options pour les développeurs › Révoquer les autorisations de débogage USB, puis rebranchez. |
| « Hors ligne » | Rebranchez le câble, puis « Redémarrer le serveur ADB » (page Appareils). Essayez un autre câble ou port. |
| « Accès USB refusé » (`no permissions`) sous Linux | Règles udev manquantes : `sudo pacman -S android-udev` (Arch) ou `sudo apt install android-sdk-platform-tools-common` (Debian/Ubuntu), puis rebranchez. |
| Téléphone invisible en mode Fastboot sous Windows | Installez le « Google USB Driver » (Windows Update › mises à jour facultatives), puis rebranchez. |
| « Plusieurs appareils » | Choisissez l'appareil cible dans la page Appareils. Pour l'installation de GrapheneOS, débranchez les autres appareils (obligatoire). |

### GrapheneOS

| Symptôme | Solution |
|----------|----------|
| « Déverrouillage OEM » grisé | Le téléphone doit avoir été connecté à Internet ; un modèle opérateur verrouillé ne peut pas être déverrouillé (aucun contournement possible). |
| Téléchargement interrompu | Relancez « Télécharger et vérifier » : il reprend où il s'était arrêté. |
| « Verification FAILED — Installation blocked » | Le fichier ne correspond pas à la signature officielle (téléchargement corrompu ou altéré). Il a été supprimé : relancez le téléchargement. Si l'échec se répète, vérifiez votre réseau (proxy, antivirus qui modifie les fichiers). |
| Contrôle préalable « Battery information available » en échec | Chargez le téléphone puis relancez les contrôles. |
| Flashage échoué | Voir la section [GrapheneOS](#grapheneos), « Si le flashage échoue » : ne verrouillez pas, rebranchez, relancez contrôles préalables et flashage. Linux : arrêtez `fwupd` (`sudo systemctl stop fwupd.service`), qui peut interrompre le mode Fastboot. |
| Vérification de sécurité impossible (étape 13) | Elle nécessite le débogage USB sur GrapheneOS ; sinon, vérifiez l'empreinte affichée au démarrage et utilisez Auditor. |

Pour tout autre problème, la page **Logs** (bouton **Exporter**) fournit un
journal sans numéros de série ni secrets, que vous pouvez joindre à un
signalement.

---

## Tests

```bash
./install.sh --dev                                   # installe pytest, pytest-cov, ruff
.venv/bin/python -m pytest                           # suite complète, aucun téléphone requis
.venv/bin/python -m pytest --cov                     # couverture des branches (seuil : 90 %)
.venv/bin/python -m pytest tests/test_scenarios.py -v   # scénarios du cahier des charges
LMS_REAL_PLATFORM_TOOLS=~/platform-tools .venv/bin/python -m pytest tests/test_real_platform_tools.py
```

Les tests installent de **faux `adb`/`fastboot` exécutables**
(`tests/fakes/fake_platform_tool.py`) pour exercer le vrai chemin `subprocess`
(timeouts, codes de sortie, sorties texte) sans matériel, un faux serveur
GrapheneOS (coupures réseau, reprise, serveur en panne) et de vraies
signatures cryptographiques produites avec une clé de test.

`tests/test_scenarios.py` rejoue de bout en bout, via l'API, chaque scénario
demandé : appareil non autorisé, hors ligne, sans permission USB, plusieurs
appareils, Pixel compatible et incompatible, téléchargement, somme de contrôle,
fichier corrompu, interruption du téléchargement, Fastboot indisponible,
**câble débranché pendant le flashage**, mauvaise image ou mauvaise version,
dossier non accessible en écriture, succès vérifié et non présumé. Matrice
complète et fonctionnement des simulations : [docs/TESTING.md](docs/TESTING.md).

Les tests qui utilisent les faux outils reposent sur un shebang POSIX et sont
ignorés sous Windows.

---

## Développement

### Mise en place

```bash
./install.sh --dev
.venv/bin/ruff check . && .venv/bin/ruff format --check .
.venv/bin/python -m pytest
.venv/bin/python -m app.main --no-browser          # http://127.0.0.1:8765/ ; schéma de l'API : /openapi.json
```

Avant chaque commit : `ruff check`, `ruff format`, la suite de tests, et pour
toute modification de l'interface, un passage dans le navigateur (bureau et
largeur mobile) sans erreur dans la console.

### Règles du projet

- **Commandes ADB/Fastboot** : uniquement via `CommandRunner.run("<nom>", …)`.
  Ajouter une commande = ajouter un `CommandSpec` à `COMMAND_WHITELIST` dans
  `app/core/platform_tools.py` (gabarit fixe, chaque paramètre validé par un
  `Arg`), avec `mutating=True` ou `destructive=True` si elle modifie le
  téléphone (elle exigera alors `confirmed=True`), puis un test. Jamais de
  `shell=True` ; l'unique exécution de script est celle du `flash-all`
  officiel, extrait de l'image vérifiée et lancé sans shell intermédiaire.
- **Erreurs** : lever une sous-classe de `LMSError` (`app/core/errors.py`)
  avec `message`, `cause`, `action` en français compréhensible ; le détail
  technique va dans `detail`.
- **Données sensibles** : ne jamais renvoyer ni journaliser un numéro de
  série (utiliser l'identifiant opaque `device_id` et `mask_serial`) ; les
  propriétés Android lues passent par la liste blanche `KEPT_PROPERTIES`.
- **Chemins** : tout chemin construit à partir d'une entrée passe par `safe_join`.
- **Interface** : insertion du contenu par `textContent` uniquement (la
  fonction `el()` de `app.js`), aucun script ni style en ligne (CSP), chaque
  vue s'enregistre avec `LMS.registerView`. Les tests de `tests/test_frontend.py`
  vérifient ces règles.
- **Rien de simulé** : pas de fonction vide, de bouton inactif ni de donnée
  factice dans l'application ; une limite d'Android se documente.

### API

L'interface n'utilise que l'API HTTP locale ; son schéma OpenAPI est servi sur
`http://127.0.0.1:8765/openapi.json` (la page interactive `/docs` est désactivée :
elle chargerait des scripts externes, interdits par la CSP). Les requêtes autres que `GET` exigent
l'en-tête `X-LMS-Token` (obtenu par `GET /api/session`). Les opérations
destructives exigent en plus `"confirm": true` dans le corps de la requête.

| Domaine | Routes |
|---------|--------|
| Système | `GET /api/health`, `/api/session`, `/api/system/environment`, `/api/settings`, `/api/settings/storage` ; `POST /api/settings/purge-temp` |
| Logs et audit | `GET /api/logs`, `/api/logs/stream` (SSE), `/api/logs/export`, `/api/audit`, `/api/audit/verify` |
| Appareils | `GET /api/device/status`, `/api/device` ; `POST /api/device/adb/restart-server` |
| Sécurité | `POST`/`GET /api/security/scan`, `GET /api/security/report`, `/api/security/boot`, `/api/security/encryption`, `/api/applications`, `/api/permissions`, `/api/network`, `/api/updates` |
| Renforcement | `GET /api/hardening/plan` ; `POST /api/hardening/apply` |
| Backup | `GET /api/backup/estimate`, `/api/backup/browse`, `/api/backup/status`, `/api/backup/list` ; `POST /api/backup/start`, `/api/backup/cancel`, `/api/backup/verify` |
| GrapheneOS | `GET /api/graphene/compatibility`, `/api/graphene/releases`, `/api/graphene/releases/{codename}`, `/api/graphene/download/status`, `/api/graphene/images`, `/api/graphene/install/status` ; `POST /api/graphene/download`, `/api/graphene/download/cancel`, `/api/graphene/verify`, `/api/graphene/images/delete`, `/api/graphene/install`, `/api/graphene/install/confirm`, `/api/graphene/install/action`, `/api/graphene/install/abandon` |

### Construire une version

```bash
scripts/build_release.sh
```

Le script lance ruff et les tests, construit `dist/*.whl` (interface incluse)
et `dist/*.tar.gz`, vérifie le contenu du wheel et écrit `dist/SHA256SUMS`.
Les Android Platform Tools et les images GrapheneOS ne sont jamais incluses.
Voir [docs/PACKAGING.md](docs/PACKAGING.md).

Feuille de route et état des phases : [docs/ROADMAP.md](docs/ROADMAP.md).

---

## Sécurité

Le serveur local pilote ADB et Fastboot ; il est donc protégé comme une
interface d'administration :

| Menace | Protection |
|--------|------------|
| Accès depuis le réseau | écoute sur l'adresse de bouclage uniquement ; une autre adresse est refusée au démarrage |
| Site web malveillant (DNS rebinding, CSRF) | en-tête `Host` filtré, jeton `X-LMS-Token` par lancement, contrôle de l'`Origin`, aucun en-tête CORS |
| Injection de commande | liste blanche, arguments validés, jamais de shell |
| Données hostiles venant du téléphone (XSS) | `textContent` uniquement, CSP `default-src 'self'` sans script en ligne |
| Image GrapheneOS altérée | signature avec clé épinglée, empreintes, contenu de l'archive, revérification avant flashage |
| Fichiers hors du dossier prévu | `safe_join` (pas de `..`, de chemin absolu, de lien symbolique sortant) |
| Fuite d'informations | numéros de série masqués, secrets retirés des logs, exceptions jamais renvoyées brutes |
| Falsification de l'historique | journal d'audit chaîné SHA-256, vérifiable depuis Paramètres |

Modèle de menace détaillé et signalement des vulnérabilités :
[docs/SECURITY.md](docs/SECURITY.md).

---

## Licence

MIT — voir [LICENSE](LICENSE).
