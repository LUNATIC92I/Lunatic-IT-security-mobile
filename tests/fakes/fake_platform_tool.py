"""Fake adb/fastboot used by the test-suite.

The fixture in ``tests/conftest.py`` installs small executable wrappers named
``adb`` and ``fastboot`` that call :func:`main`. Behaviour is driven by the
``LMS_FAKE_SCENARIO`` environment variable so the real subprocess path of
``CommandRunner`` is exercised without a phone.

Scenarios: ``normal`` (default), ``old_fastboot``, ``hang``, ``fail``,
``garbage``.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path


def _record_call(tool: str, args: list[str]) -> None:
    log_path = os.environ.get("LMS_FAKE_CALL_LOG")
    if log_path:
        with Path(log_path).open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"tool": tool, "args": args}) + "\n")


def main(tool: str, args: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if args is None else args)
    _record_call(tool, args)
    scenario = os.environ.get("LMS_FAKE_SCENARIO", "normal")
    if scenario == "hang":
        time.sleep(30)
        return 0
    if scenario == "fail":
        sys.stderr.write("error: fake failure\n")
        return 1
    if scenario == "garbage":
        sys.stdout.write("something unexpected\n")
        return 0

    if tool == "adb":
        if args == ["version"]:
            sys.stdout.write("Android Debug Bridge version 1.0.41\nVersion 35.0.2-12147458\nInstalled as /fake/adb\n")
            return 0
        if args == ["devices", "-l"]:
            sys.stdout.write("List of devices attached\n\n")
            return 0
        if args == ["start-server"]:
            return 0
    if tool == "fastboot":
        if args == ["--version"]:
            version = "34.0.5-10900879" if scenario == "old_fastboot" else "35.0.2-12147458"
            sys.stdout.write(f"fastboot version {version}\nInstalled as /fake/fastboot\n")
            return 0
        if args == ["devices"]:
            return 0
    sys.stderr.write(f"{tool}: unknown command {' '.join(args)}\n")
    return 1
