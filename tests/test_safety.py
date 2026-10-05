import pytest

from app.core.errors import InvalidInputError, PathSecurityError
from app.core.safety import mask_serial, safe_join, validate_filename, validate_serial


@pytest.mark.parametrize(
    "serial", ["0A1B2C3D4E", "192.168.1.20:5555", "emulator-5554", "adb-1A2B._adb-tls-connect._tcp"]
)
def test_valid_serials(serial):
    assert validate_serial(serial) == serial


@pytest.mark.parametrize("serial", ["", "-s", "abc def", "abc;rm -rf /", "a$(id)", "a`id`", "x" * 200, "a\nb", None])
def test_invalid_serials(serial):
    with pytest.raises(InvalidInputError):
        validate_serial(serial)


def test_mask_serial():
    assert mask_serial("0A1B2C3D4E") == "0A••••••4E"
    assert mask_serial("abc") == "•••"
    assert mask_serial(None) == ""


def test_safe_join_accepts_children(tmp_path):
    assert safe_join(tmp_path, "a", "b.txt") == (tmp_path / "a" / "b.txt").resolve()


@pytest.mark.parametrize("parts", [("..", "etc", "passwd"), ("a/../../x",), ("/etc/passwd",), ("",), ("a\x00b",)])
def test_safe_join_rejects_traversal(tmp_path, parts):
    with pytest.raises(PathSecurityError):
        safe_join(tmp_path, *parts)


def test_safe_join_rejects_symlink_escape(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    base = tmp_path / "base"
    base.mkdir()
    try:
        (base / "link").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks not permitted")
    with pytest.raises(PathSecurityError):
        safe_join(base, "link", "file")


@pytest.mark.parametrize("name", ["../x", "a/b", ".hidden", "a b", "", "x..y"])
def test_validate_filename_rejects(name):
    with pytest.raises(PathSecurityError):
        validate_filename(name)


def test_validate_filename_accepts():
    assert validate_filename("husky-factory-2026100500.zip") == "husky-factory-2026100500.zip"
