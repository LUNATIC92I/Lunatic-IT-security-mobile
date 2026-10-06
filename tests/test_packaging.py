"""Packaging: what an installed wheel contains and where it looks for its files."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from app import config
from app.config import PROJECT_ROOT

pytestmark = pytest.mark.skipif(sys.version_info < (3, 11), reason="tomllib requires Python 3.11")


def _pyproject() -> dict:
    import tomllib

    return tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_every_python_package_is_shipped():
    """A new sub-package missing from pyproject.toml would be absent from the wheel."""
    declared = set(_pyproject()["tool"]["setuptools"]["packages"])
    on_disk = {
        ".".join(init.parent.relative_to(PROJECT_ROOT).parts) for init in (PROJECT_ROOT / "app").rglob("__init__.py")
    }
    assert on_disk <= declared, sorted(on_disk - declared)


def test_every_frontend_file_is_shipped():
    """Each interface file matches a package-data pattern of app.frontend."""
    patterns = _pyproject()["tool"]["setuptools"]["package-data"]["app.frontend"]
    frontend = PROJECT_ROOT / "frontend"
    for path in frontend.rglob("*"):
        if path.is_file():
            relative = path.relative_to(frontend)
            assert any(relative.match(pattern) for pattern in patterns), f"not packaged: {relative}"


def test_entry_point_targets_cli():
    scripts = _pyproject()["project"]["scripts"]
    assert scripts == {"lunatic-mobile-security": "app.main:cli"}
    from app.main import cli

    assert callable(cli)


def test_frontend_dir_prefers_bundled_copy(tmp_path: Path):
    package_dir, project_root = tmp_path / "site-packages" / "app", tmp_path / "src"
    assert config._frontend_dir(package_dir, project_root) == project_root / "frontend"  # source checkout
    (package_dir / "frontend").mkdir(parents=True)
    (package_dir / "frontend" / "index.html").write_text("<!doctype html>")
    assert config._frontend_dir(package_dir, project_root) == package_dir / "frontend"  # installed wheel


def test_cli_refuses_to_start_without_interface(monkeypatch, tmp_path, capsys):
    from app import main

    monkeypatch.setattr(main, "FRONTEND_DIR", tmp_path / "missing")
    monkeypatch.setenv("LMS_DATA_DIR", str(tmp_path / "data"))
    main.get_settings.cache_clear()
    try:
        assert main.cli(["--no-browser", "--port", "18765"]) == 1
    finally:
        main.get_settings.cache_clear()
    err = capsys.readouterr().err
    assert "ERREUR" in err and "ACTION" in err and "interface" in err


def test_env_files_per_user_then_source_checkout():
    """Installed package: <data dir>/.env; source checkout: its .env wins (later file)."""
    from app.config import Settings, default_data_dir

    assert Settings.model_config["env_file"] == (default_data_dir() / ".env", PROJECT_ROOT / ".env")
