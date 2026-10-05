import json

from app import main
from tests.conftest import POSIX_ONLY


@POSIX_ONLY
def test_check_json(monkeypatch, capsys, tmp_path, fake_tools_dir, isolated_path):
    monkeypatch.setenv("LMS_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("LMS_PLATFORM_TOOLS_DIR", str(fake_tools_dir))
    assert main.cli(["--check", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["tools"]["fastboot"]["found"] is True


def test_check_text_fails_without_tools(monkeypatch, capsys, tmp_path, isolated_path):
    monkeypatch.setenv("LMS_DATA_DIR", str(tmp_path / "data"))
    assert main.cli(["--check"]) == 1
    out = capsys.readouterr().out
    assert "adb introuvable" in out and "→" in out


def test_invalid_configuration(monkeypatch, capsys):
    monkeypatch.setenv("LMS_HOST", "0.0.0.0")
    assert main.cli(["--check"]) == 2
    assert "ERREUR" in capsys.readouterr().err


def test_port_in_use(monkeypatch, capsys, tmp_path):
    import socket

    monkeypatch.setenv("LMS_DATA_DIR", str(tmp_path / "data"))
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        port = sock.getsockname()[1]
        if port < 1024:
            return
        assert main.cli(["--port", str(port), "--no-browser"]) == 1
    assert "déjà utilisé" in capsys.readouterr().err
