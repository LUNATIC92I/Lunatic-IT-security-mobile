#!/usr/bin/env bash
# LUNATIC MOBILE SECURITY - build the distributable packages.
# Produces dist/<name>-<version>.tar.gz (sources), dist/<name>-<version>-py3-none-any.whl
# (installable package, interface included) and dist/SHA256SUMS.
# Usage: scripts/build_release.sh      (requires ./install.sh --dev)
set -euo pipefail
cd "$(dirname "$0")/.."

PYTHON=".venv/bin/python"
if [ ! -x "${PYTHON}" ]; then
    echo "ERREUR : environnement .venv introuvable." >&2
    echo "ACTION : lancez d'abord ./install.sh --dev" >&2
    exit 1
fi

echo "==> Contrôles (ruff, tests)"
"${PYTHON}" -m ruff check .
"${PYTHON}" -m ruff format --check .
"${PYTHON}" -m pytest -q -p no:cacheprovider

echo "==> Construction"
rm -rf dist build ./*.egg-info
"${PYTHON}" -m build

echo "==> Vérification du contenu du wheel"
WHEEL="$(ls dist/*.whl)"
"${PYTHON}" - "${WHEEL}" <<'PY'
import sys
import zipfile

names = set(zipfile.ZipFile(sys.argv[1]).namelist())
required = {"app/main.py", "app/frontend/index.html", "app/frontend/js/app.js", "app/frontend/css/main.css"}
missing = sorted(required - names)
if missing:
    sys.exit(f"ERREUR : fichiers absents du wheel : {missing}")
print(f"OK : {len(names)} fichiers, interface incluse")
PY

echo "==> Empreintes"
(cd dist && if command -v sha256sum >/dev/null 2>&1; then sha256sum -- *.whl *.tar.gz; else shasum -a 256 -- *.whl *.tar.gz; fi) > dist/SHA256SUMS.tmp
mv dist/SHA256SUMS.tmp dist/SHA256SUMS
cat dist/SHA256SUMS
echo "Paquets prêts dans dist/ (vérification : cd dist && sha256sum -c SHA256SUMS)"
