import pytest
from pydantic import ValidationError

from app.config import HostOS, Settings, default_data_dir, detect_host_os


@pytest.mark.parametrize(
    ("name", "expected"),
    [("win32", HostOS.WINDOWS), ("darwin", HostOS.MACOS), ("linux", HostOS.LINUX), ("freebsd13", HostOS.UNKNOWN)],
)
def test_detect_host_os(name, expected):
    assert detect_host_os(name) is expected


def test_default_data_dir_per_platform(monkeypatch, tmp_path):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    assert default_data_dir(HostOS.WINDOWS) == tmp_path / "local" / "LunaticMobileSecurity"
    assert default_data_dir(HostOS.MACOS).parts[-3:] == ("Library", "Application Support", "LunaticMobileSecurity")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    assert default_data_dir(HostOS.LINUX) == tmp_path / "xdg" / "lunatic-mobile-security"


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "localhost", "127.0.0.2"])
def test_loopback_hosts_accepted(host):
    assert Settings(host=host, _env_file=None).host == host


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.10", "::", "example.com"])
def test_non_loopback_hosts_refused(host):
    with pytest.raises(ValidationError):
        Settings(host=host, _env_file=None)


@pytest.mark.parametrize(
    "url",
    [
        "http://releases.grapheneos.org",
        "https://evil.example.com",
        "https://releases.grapheneos.org.evil.com",
        "https://user:pass@releases.grapheneos.org",
        "https://releases.grapheneos.org/?x=1",
    ],
)
def test_graphene_endpoint_must_be_official_https(url):
    with pytest.raises(ValidationError):
        Settings(grapheneos_releases_url=url, _env_file=None)


def test_graphene_endpoint_normalised():
    assert Settings(
        grapheneos_releases_url="https://releases.grapheneos.org/", _env_file=None
    ).grapheneos_releases_url == ("https://releases.grapheneos.org")


def test_invalid_log_level_and_port():
    with pytest.raises(ValidationError):
        Settings(log_level="LOUD", _env_file=None)
    with pytest.raises(ValidationError):
        Settings(port=80, _env_file=None)
    assert Settings(log_level="warn", _env_file=None).log_level == "WARNING"


def test_env_variables_are_read(monkeypatch, tmp_path):
    monkeypatch.setenv("LMS_PORT", "9123")
    monkeypatch.setenv("LMS_DATA_DIR", str(tmp_path))
    settings = Settings(_env_file=None)
    assert settings.port == 9123
    assert settings.resolved_data_dir == tmp_path.resolve()


def test_ensure_directories_owner_only(tmp_path):
    settings = Settings(data_dir=tmp_path / "d", _env_file=None)
    settings.ensure_directories()
    for directory in (settings.logs_dir, settings.downloads_dir, settings.backups_dir, settings.temp_dir):
        assert directory.is_dir()
        if settings.host_os is not HostOS.WINDOWS:
            assert directory.stat().st_mode & 0o777 == 0o700


def test_public_view_has_no_unexpected_keys(tmp_path):
    view = Settings(data_dir=tmp_path, _env_file=None).public_view()
    assert view["min_fastboot_version"] == "35.0.1"
    assert set(view) == {
        "host",
        "port",
        "host_os",
        "data_dir",
        "logs_dir",
        "downloads_dir",
        "backups_dir",
        "platform_tools_dir",
        "log_level",
        "command_timeout",
        "flash_timeout",
        "grapheneos_releases_url",
        "min_fastboot_version",
    }
