import json
import subprocess

import pytest

from app.core import platform_tools
from app.core.errors import (
    CommandNotAllowedError,
    InvalidInputError,
    ToolExecutionError,
    ToolNotFoundError,
    ToolTimeoutError,
)
from app.core.platform_tools import (
    COMMAND_WHITELIST,
    Arg,
    CommandRunner,
    CommandSpec,
    Tool,
    inspect_tool,
    parse_adb_version,
    parse_fastboot_version,
    version_at_least,
)
from tests.conftest import POSIX_ONLY

pytestmark = POSIX_ONLY


def test_locator_prefers_configured_dir(settings, fake_tools_dir):
    runner = CommandRunner(settings)
    assert runner.locator.locate(Tool.ADB) == (fake_tools_dir / "adb").resolve()


def test_runner_executes_real_subprocess(settings):
    result = CommandRunner(settings).run("adb.version")
    assert result.ok
    assert parse_adb_version(result.stdout) == "35.0.2-12147458"
    assert result.argv_display == ["adb", "version"]


def test_unknown_command_refused(settings):
    with pytest.raises(CommandNotAllowedError):
        CommandRunner(settings).run("adb.shell_anything")


def test_raw_argv_cannot_be_passed(settings):
    with pytest.raises(TypeError):
        CommandRunner(settings).run(["adb", "shell", "rm", "-rf", "/"])  # type: ignore[arg-type]


def test_tool_missing(settings_without_tools):
    with pytest.raises(ToolNotFoundError) as exc:
        CommandRunner(settings_without_tools).run("adb.version")
    assert "Platform Tools" in exc.value.action


def test_timeout_kills_process(settings, monkeypatch):
    monkeypatch.setenv("LMS_FAKE_SCENARIO", "hang")
    with pytest.raises(ToolTimeoutError):
        CommandRunner(settings).run("adb.version", timeout=1)


def test_check_raises_on_failure(settings, monkeypatch):
    monkeypatch.setenv("LMS_FAKE_SCENARIO", "fail")
    result = CommandRunner(settings).run("adb.version")
    assert result.returncode == 1 and "fake failure" in result.stderr
    with pytest.raises(ToolExecutionError) as exc:
        CommandRunner(settings).run("adb.version", check=True)
    assert "fake failure" in exc.value.detail


def test_never_uses_shell(settings, monkeypatch):
    calls = []
    real_run = subprocess.run

    def spy(*args, **kwargs):
        calls.append((args, kwargs))
        return real_run(*args, **kwargs)

    monkeypatch.setattr(platform_tools.subprocess, "run", spy)
    CommandRunner(settings).run("fastboot.version")
    ((args, kwargs),) = calls
    assert kwargs["shell"] is False
    assert isinstance(args[0], list)
    assert kwargs["stdin"] is subprocess.DEVNULL
    assert kwargs["timeout"] > 0


def test_command_receives_exact_argv(settings, monkeypatch, tmp_path):
    log = tmp_path / "calls.jsonl"
    monkeypatch.setenv("LMS_FAKE_CALL_LOG", str(log))
    CommandRunner(settings).run("adb.devices")
    assert json.loads(log.read_text().splitlines()[0]) == {"tool": "adb", "args": ["devices", "-l"]}


# --- template / argument validation (no subprocess) ------------------------

PROP = Arg("prop", r"[a-z0-9._]+")
SPEC = CommandSpec("test.getprop", Tool.ADB, ("shell", "getprop", PROP), requires_serial=True)


def test_spec_builds_with_serial():
    assert SPEC.build("ABC123", {"prop": "ro.product.model"}) == [
        "-s",
        "ABC123",
        "shell",
        "getprop",
        "ro.product.model",
    ]


@pytest.mark.parametrize("value", ["-x", "ro.a;reboot", "a b", "$(id)", "", "x" * 500])
def test_spec_rejects_injection(value):
    with pytest.raises(InvalidInputError):
        SPEC.build("ABC123", {"prop": value})


def test_spec_requires_serial_and_rejects_extra_params():
    with pytest.raises(InvalidInputError):
        SPEC.build(None, {"prop": "ro.x"})
    with pytest.raises(InvalidInputError):
        SPEC.build("ABC123", {"prop": "ro.x", "extra": "1"})
    with pytest.raises(InvalidInputError):
        SPEC.build("ABC123", {})
    with pytest.raises(InvalidInputError):
        COMMAND_WHITELIST["adb.version"].build("ABC123", None)


def test_destructive_requires_confirmation(settings, monkeypatch):
    spec = CommandSpec("test.wipe", Tool.FASTBOOT, ("-w",), destructive=True)
    monkeypatch.setitem(COMMAND_WHITELIST, spec.name, spec)
    with pytest.raises(CommandNotAllowedError):
        CommandRunner(settings).run("test.wipe")


def test_whitelist_is_static_and_safe():
    for name, spec in COMMAND_WHITELIST.items():
        assert name == spec.name and name.startswith(spec.tool.value + ".")
        for part in spec.template:
            if isinstance(part, str):
                assert not any(ch in part for ch in ";|&$`<>\n ")


# --- version parsing --------------------------------------------------------


def test_version_parsing():
    assert parse_fastboot_version("fastboot version 35.0.2-12147458\nInstalled as x") == "35.0.2-12147458"
    assert parse_adb_version("Android Debug Bridge version 1.0.41\n") == "1.0.41"
    assert version_at_least("35.0.2-12147458", "35.0.1")
    assert version_at_least("35.0.1", "35.0.1")
    assert not version_at_least("34.0.5-10900879", "35.0.1")
    assert not version_at_least(None, "35.0.1")
    assert not version_at_least("debian-snapshot", "35.0.1")


def test_inspect_tool_reports_old_fastboot(settings, monkeypatch):
    monkeypatch.setenv("LMS_FAKE_SCENARIO", "old_fastboot")
    info = inspect_tool(CommandRunner(settings), Tool.FASTBOOT)
    assert info.found and info.version == "34.0.5-10900879"
    assert info.meets_minimum is False and info.notes


def test_inspect_tool_unparseable_version(settings, monkeypatch):
    monkeypatch.setenv("LMS_FAKE_SCENARIO", "garbage")
    info = inspect_tool(CommandRunner(settings), Tool.FASTBOOT)
    assert info.version is None and info.meets_minimum is False


def test_inspect_tool_missing(settings_without_tools):
    info = inspect_tool(CommandRunner(settings_without_tools), Tool.ADB)
    assert not info.found and info.error["code"] == "tool_not_found"
