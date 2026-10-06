# Packaging et distribution

Le logiciel se distribue de trois façons. Toutes installent la même application
(serveur Python + interface web) et s'utilisent de la même manière.

| Méthode | Pour qui | Commande de lancement |
|---------|----------|------------------------|
| Dépôt source + script d'installation | utilisateurs, développeurs | `.venv/bin/python -m app.main` |
| Paquet wheel avec **pipx** (recommandé pour une installation « logiciel ») | utilisateurs | `lunatic-mobile-security` |
| Paquet wheel avec `pip` dans un environnement virtuel dédié | intégrateurs | `<venv>/bin/lunatic-mobile-security` |

Le nom d'import du code est `app` (structure du projet). Installez donc
toujours le paquet dans un **environnement isolé** (pipx ou venv dédié), jamais
dans l'environnement Python du système ou d'un autre projet.

## Construire les paquets

```bash
./install.sh --dev
scripts/build_release.sh
```

Le script lance ruff et la suite de tests, construit les paquets, vérifie que
l'interface est bien incluse dans le wheel, puis écrit les empreintes :

```
dist/
  lunatic_mobile_security-0.1.0-py3-none-any.whl   paquet installable (pur Python, toutes plateformes)
  lunatic_mobile_security-0.1.0.tar.gz             sources (code, interface, tests, docs, scripts)
  SHA256SUMS                                       empreintes à publier avec les paquets
```

Le wheel embarque le dossier `frontend/` sous `app/frontend/`
(`[tool.setuptools] package-dir` dans `pyproject.toml`) ; `app.config.FRONTEND_DIR`
utilise cette copie quand elle existe, sinon le dossier `frontend/` du dépôt.
`tests/test_packaging.py` échoue si un sous-paquet Python ou un fichier de
l'interface n'est pas déclaré.

## Installer un paquet

Vérifiez d'abord l'empreinte du fichier reçu :

```bash
sha256sum -c SHA256SUMS                    # Linux
shasum -a 256 -c SHA256SUMS                # macOS
```
```powershell
(Get-FileHash lunatic_mobile_security-0.1.0-py3-none-any.whl).Hash   # Windows : comparer avec SHA256SUMS
```

### Linux

```bash
sudo apt install pipx    # Debian/Ubuntu ; Arch : sudo pacman -S python-pipx ; Fedora : sudo dnf install pipx
pipx ensurepath
pipx install ./lunatic_mobile_security-0.1.0-py3-none-any.whl
lunatic-mobile-security --check
lunatic-mobile-security
```

Prérequis restant à la charge du système : Android Platform Tools officielles
et règles udev (README › Installation Android Platform Tools).

### macOS

```bash
brew install pipx && pipx ensurepath
pipx install ./lunatic_mobile_security-0.1.0-py3-none-any.whl
lunatic-mobile-security
```

Lancé depuis le Dock ou le Finder, un programme reçoit un `PATH` minimal :
renseignez `LMS_PLATFORM_TOOLS_DIR` dans le fichier de configuration (voir
ci-dessous) plutôt que de compter sur le `PATH`. Le flashage GrapheneOS utilise
`/bin/bash`, présent sur tous les macOS.

### Windows

```powershell
py -m pip install --user pipx
py -m pipx ensurepath          # puis rouvrir PowerShell
pipx install .\lunatic_mobile_security-0.1.0-py3-none-any.whl
lunatic-mobile-security
```

Installez aussi le « Google USB Driver » (Windows Update › mises à jour
facultatives). Le flashage GrapheneOS exécute le script officiel
`flash-all.bat` via `cmd.exe`.

## Configuration d'une installation par paquet

Une installation par paquet n'a pas de dossier de projet : placez le fichier de
configuration dans le répertoire de données de l'utilisateur, sous le nom
`.env` (même format que `.env.example`) :

| Système | Fichier |
|---------|---------|
| Linux | `~/.local/share/lunatic-mobile-security/.env` |
| macOS | `~/Library/Application Support/LunaticMobileSecurity/.env` |
| Windows | `%LOCALAPPDATA%\LunaticMobileSecurity\.env` |

Ordre de priorité : variables d'environnement, puis `.env` du dépôt source
(s'il existe), puis `.env` du répertoire de données. Ce fichier est toujours
lu à l'emplacement par défaut : un `LMS_DATA_DIR` qu'il contient déplace les
données (logs, images, sauvegardes), pas le fichier de configuration lui-même.

## Raccourcis de lancement (installation depuis le dépôt)

```bash
./install.sh --shortcut          # Linux : menu Applications ; macOS : ~/Applications
```
```powershell
powershell -ExecutionPolicy Bypass -File scripts\install.ps1 -Shortcut   # menu Démarrer
```

Le raccourci ouvre une fenêtre de terminal (les messages et `Ctrl+C` pour
quitter y restent visibles) puis l'interface dans le navigateur.

## Mise à jour et désinstallation

```bash
pipx install --force ./lunatic_mobile_security-<nouvelle version>-py3-none-any.whl
pipx uninstall lunatic-mobile-security
```

La désinstallation ne supprime pas le répertoire de données (logs, rapports,
images GrapheneOS, sauvegardes par défaut) : supprimez-le vous-même après avoir
mis vos sauvegardes à l'abri. Raccourcis éventuels :
`~/.local/share/applications/lunatic-mobile-security.desktop` (Linux),
`~/Applications/LUNATIC MOBILE SECURITY.command` (macOS),
menu Démarrer › `LUNATIC MOBILE SECURITY` (Windows).

## Ce qui n'est pas inclus, volontairement

- **Android Platform Tools** : distribuées par Google sous leur propre licence ;
  l'utilisateur les télécharge depuis la source officielle et en vérifie
  l'empreinte (README).
- **Images GrapheneOS** : jamais hébergées ni redistribuées ; téléchargées
  depuis `releases.grapheneos.org` et vérifiées au moment de l'installation.
- **Exécutable autonome** (PyInstaller, .app, .exe signé) : non fourni. Un
  binaire non signé déclencherait les avertissements de Gatekeeper et de
  SmartScreen et serait plus difficile à vérifier qu'un paquet Python
  accompagné de ses empreintes.
