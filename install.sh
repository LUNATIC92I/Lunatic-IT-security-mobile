#!/usr/bin/env bash
# LUNATIC MOBILE SECURITY - installation script for Linux and macOS.
# Creates a virtual environment in .venv, installs dependencies and runs the
# environment diagnostic. Does not require root and installs nothing system-wide.
set -euo pipefail

cd "$(dirname "$0")"

usage() {
    cat <<USAGE
Usage : ./install.sh [--dev] [--shortcut]
  --dev       installe aussi les outils de test et de build (pytest, ruff, build)
  --shortcut  crée un raccourci de lancement (menu Applications sous Linux,
              dossier ~/Applications sous macOS)
USAGE
}

DEV=0
SHORTCUT=0
for arg in "$@"; do
    case "${arg}" in
        --dev) DEV=1 ;;
        --shortcut) SHORTCUT=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "ERREUR : option inconnue : ${arg}" >&2; usage >&2; exit 2 ;;
    esac
done

case "$(uname -s)" in
    Linux*)  PLATFORM="Linux" ;;
    Darwin*) PLATFORM="macOS" ;;
    *) echo "ERREUR : système non pris en charge par ce script ($(uname -s)). Sous Windows utilisez scripts\\install.ps1." >&2; exit 1 ;;
esac
echo "==> Plateforme détectée : ${PLATFORM} ($(uname -m))"

PYTHON="${PYTHON:-}"
if [ -z "${PYTHON}" ]; then
    for candidate in python3.13 python3.12 python3.11 python3.10 python3; do
        if command -v "${candidate}" >/dev/null 2>&1; then PYTHON="${candidate}"; break; fi
    done
fi
if [ -z "${PYTHON}" ]; then
    echo "ERREUR : Python 3.10+ introuvable." >&2
    echo "ACTION : installez Python 3.10 ou plus récent (https://www.python.org/downloads/)." >&2
    exit 1
fi
if ! "${PYTHON}" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then
    echo "ERREUR : $("${PYTHON}" --version) détecté, Python 3.10+ requis." >&2
    exit 1
fi
echo "==> Python : $("${PYTHON}" --version)"

if ! "${PYTHON}" -m venv --help >/dev/null 2>&1; then
    echo "ERREUR : le module venv est absent." >&2
    echo "ACTION (Debian/Ubuntu) : sudo apt install python3-venv" >&2
    exit 1
fi

if [ ! -d .venv ]; then
    echo "==> Création de l'environnement virtuel .venv"
    "${PYTHON}" -m venv .venv
fi

echo "==> Installation des dépendances"
.venv/bin/python -m pip install --upgrade pip >/dev/null
if [ "${DEV}" = "1" ]; then
    .venv/bin/python -m pip install -r requirements-dev.txt
else
    .venv/bin/python -m pip install -r requirements.txt
fi

if [ "${SHORTCUT}" = "1" ]; then
    PROJECT_DIR="$(pwd)"
    if [ "${PLATFORM}" = "Linux" ]; then
        APPS_DIR="${XDG_DATA_HOME:-${HOME}/.local/share}/applications"
        mkdir -p "${APPS_DIR}"
        DESKTOP_FILE="${APPS_DIR}/lunatic-mobile-security.desktop"
        cat > "${DESKTOP_FILE}" <<DESKTOP
[Desktop Entry]
Type=Application
Name=LUNATIC MOBILE SECURITY
Comment=Audit de sécurité Android et installation officielle de GrapheneOS
Exec="${PROJECT_DIR}/.venv/bin/python" -m app.main
Path=${PROJECT_DIR}
Icon=${PROJECT_DIR}/frontend/favicon.svg
Terminal=true
Categories=Utility;Security;
DESKTOP
        chmod 0644 "${DESKTOP_FILE}"
        echo "==> Raccourci créé : ${DESKTOP_FILE}"
    else
        mkdir -p "${HOME}/Applications"
        COMMAND_FILE="${HOME}/Applications/LUNATIC MOBILE SECURITY.command"
        cat > "${COMMAND_FILE}" <<COMMAND
#!/usr/bin/env bash
cd "${PROJECT_DIR}" && exec "${PROJECT_DIR}/.venv/bin/python" -m app.main
COMMAND
        chmod 0755 "${COMMAND_FILE}"
        echo "==> Raccourci créé : ${COMMAND_FILE}"
    fi
fi

echo "==> Diagnostic de l'environnement"
.venv/bin/python -m app.main --check || true

cat <<MSG

Installation terminée.
Lancer l'application :   .venv/bin/python -m app.main
Diagnostic seul :        .venv/bin/python -m app.main --check
MSG
