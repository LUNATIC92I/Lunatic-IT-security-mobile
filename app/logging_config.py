"""Structured application logging.

Output format (console and file)::

    2026-10-05 17:00:02 INFO Device detected

Guarantees:

* secrets (``password=``, ``token=``, ``Authorization:`` ...) are redacted;
* device serials registered through :func:`register_sensitive_value` are
  replaced by their masked form everywhere, including in exception text;
* the last records are kept in memory with a monotonic id so the UI can poll
  ``/api/logs?since=<id>`` for real-time logs.
"""

from __future__ import annotations

import itertools
import logging
import re
import threading
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path

from app.core.safety import mask_serial

LOGGER_NAME = "lms"
LOG_FORMAT = "%(asctime)s %(levelname)s %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
LEVEL_NAMES = {"WARNING": "WARN", "CRITICAL": "CRIT"}

_SECRET_PATTERNS = [
    re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|passphrase|pin)\b(\s*[=:]\s*)(\S+)"),
    re.compile(r"(?i)(authorization\s*:\s*)(\S+(?:\s+\S+)?)"),
]

_sensitive_values: set[str] = set()
_sensitive_lock = threading.Lock()


def register_sensitive_value(value: str | None) -> None:
    """Mask ``value`` (typically a device serial) in every future log line."""
    if value and len(value) >= 4:
        with _sensitive_lock:
            _sensitive_values.add(value)


def redact(text: str) -> str:
    for pattern in _SECRET_PATTERNS:
        if pattern.groups == 3:
            text = pattern.sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", text)
        else:
            text = pattern.sub(lambda m: f"{m.group(1)}[REDACTED]", text)
    with _sensitive_lock:
        values = sorted(_sensitive_values, key=len, reverse=True)
    for value in values:
        if value in text:
            text = text.replace(value, mask_serial(value))
    return text


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        if record.exc_info and not record.exc_text:
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        if record.exc_text:
            record.exc_text = redact(record.exc_text)
        record.msg = redact(message)
        record.args = None
        record.levelname = LEVEL_NAMES.get(record.levelname, record.levelname)
        return True


@dataclass(frozen=True)
class LogEntry:
    id: int
    timestamp: str
    level: str
    logger: str
    message: str


class MemoryLogHandler(logging.Handler):
    """Keeps the latest log records for the UI log viewer."""

    def __init__(self, capacity: int = 2000) -> None:
        super().__init__()
        self._entries: deque[LogEntry] = deque(maxlen=capacity)
        self._counter = itertools.count(1)
        self._lock_entries = threading.Lock()

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = record.getMessage()
            if record.exc_text:
                message = f"{message}\n{record.exc_text}"
            with self._lock_entries:
                self._entries.append(
                    LogEntry(
                        id=next(self._counter),
                        timestamp=datetime.fromtimestamp(record.created).strftime(DATE_FORMAT),
                        level=record.levelname,
                        logger=record.name,
                        message=message,
                    )
                )
        except Exception:  # pragma: no cover - logging must never raise
            self.handleError(record)

    def entries(self, since: int = 0, limit: int = 500, min_level: str | None = None) -> list[dict]:
        threshold = _level_value(min_level) if min_level else 0
        with self._lock_entries:
            selected = [e for e in self._entries if e.id > since and _level_value(e.level) >= threshold]
        return [asdict(e) for e in selected[-limit:]]


_LEVEL_VALUES = {"DEBUG": 10, "INFO": 20, "WARN": 30, "WARNING": 30, "ERROR": 40, "CRIT": 50, "CRITICAL": 50}


def _level_value(name: str) -> int:
    return _LEVEL_VALUES.get(name.upper(), 0)


_memory_handler = MemoryLogHandler()


def get_memory_handler() -> MemoryLogHandler:
    return _memory_handler


def get_logger(name: str | None = None) -> logging.Logger:
    return logging.getLogger(f"{LOGGER_NAME}.{name}" if name else LOGGER_NAME)


def configure_logging(level: str = "INFO", log_file: Path | None = None, console: bool = True) -> logging.Logger:
    """(Re)configure the application logger. Safe to call several times."""
    logger = logging.getLogger(LOGGER_NAME)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        if handler is not _memory_handler:
            handler.close()

    logger.setLevel(level)
    logger.propagate = False
    formatter = logging.Formatter(LOG_FORMAT, DATE_FORMAT)
    # Filters are attached to handlers (not the logger) so that records emitted by
    # child loggers such as "lms.adb" are redacted too.
    redacting_filter = RedactingFilter()

    if console:
        stream = logging.StreamHandler()
        stream.setFormatter(formatter)
        stream.addFilter(redacting_filter)
        logger.addHandler(stream)
    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8")
        file_handler.setFormatter(formatter)
        file_handler.addFilter(redacting_filter)
        logger.addHandler(file_handler)
    _memory_handler.setFormatter(formatter)
    for existing_filter in list(_memory_handler.filters):
        _memory_handler.removeFilter(existing_filter)
    _memory_handler.addFilter(redacting_filter)
    logger.addHandler(_memory_handler)
    return logger
