#!/usr/bin/env bash
# LUNATIC MOBILE SECURITY - installation script for Linux and macOS.
# Creates a virtual environment in .venv, installs dependencies and runs the
# environment diagnostic. Does not require root and installs nothing system-wide.
set -euo pipefail

cd "$(dirname "$0")"

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
if [ "${1:-}" = "--dev" ]; then
    .venv/bin/python -m pip install -r requirements-dev.txt
else
    .venv/bin/python -m pip install -r requirements.txt
fi

echo "==> Diagnostic de l'environnement"
.venv/bin/python -m app.main --check || true

cat <<MSG

Installation terminée.
Lancer l'application :   .venv/bin/python -m app.main
Diagnostic seul :        .venv/bin/python -m app.main --check
MSG
