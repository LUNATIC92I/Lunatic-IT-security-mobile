"""Tamper-evident audit trail for sensitive operations.

Each event is appended to a JSON Lines file. Every line embeds the SHA-256 hash
of the previous line (``prev_hash``) and its own hash, forming a hash chain:
modifying or deleting a past event breaks the chain, which
:meth:`AuditLogger.verify` detects.

The chain makes tampering *detectable*, not impossible: someone with write
access to the file can rewrite the whole chain. It is meant to give the user a
trustworthy local history of what the software did to their phone.

Details are sanitized before being written: keys that look like secrets are
dropped and ``serial`` values are masked.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.core.safety import mask_serial
from app.logging_config import get_logger

GENESIS_HASH = "0" * 64
_SECRET_KEYS = ("password", "passwd", "secret", "token", "apikey", "api_key", "passphrase", "pin", "authorization")
_MAX_STRING = 2000

log = get_logger("audit")


def _sanitize(value: Any, key: str = "") -> Any:
    lowered = key.lower()
    if any(secret in lowered for secret in _SECRET_KEYS):
        return "[REDACTED]"
    if lowered in {"serial", "serial_number", "device_serial"} and isinstance(value, str):
        return mask_serial(value)
    if isinstance(value, dict):
        return {str(k): _sanitize(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sanitize(v) for v in value]
    if isinstance(value, str):
        return value[:_MAX_STRING]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:_MAX_STRING]


def _hash_record(record: dict[str, Any]) -> str:
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ChainVerification:
    valid: bool
    events: int
    first_invalid_line: int | None = None
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "events": self.events,
            "first_invalid_line": self.first_invalid_line,
            "reason": self.reason,
        }


class AuditLogger:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._last_hash: str | None = None

    def _read_last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS_HASH
        last_line = ""
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    last_line = line
        if not last_line:
            return GENESIS_HASH
        try:
            return json.loads(last_line)["hash"]
        except (json.JSONDecodeError, KeyError):
            # A corrupted tail must not silently restart the chain from genesis:
            # anchor on the hash of the raw line so verify() still reports it.
            return hashlib.sha256(last_line.encode("utf-8")).hexdigest()

    def record(self, event: str, level: str = "INFO", **details: Any) -> dict[str, Any]:
        """Append an event. ``event`` is a short snake_case identifier."""
        with self._lock:
            if self._last_hash is None:
                self._last_hash = self._read_last_hash()
            body = {
                "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "event": str(event)[:100],
                "level": level.upper(),
                "details": _sanitize(details),
                "prev_hash": self._last_hash,
            }
            body["hash"] = _hash_record(body)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            is_new = not self.path.exists()
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(body, ensure_ascii=False) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            if is_new and os.name != "nt":
                os.chmod(self.path, 0o600)
            self._last_hash = body["hash"]
        log.debug("Audit event recorded: %s", event)
        return body

    def read(self, limit: int = 200) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        events: list[dict[str, Any]] = []
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    events.append({"event": "corrupted_line", "level": "ERROR", "details": {}})
        return events[-limit:]

    def verify(self) -> ChainVerification:
        if not self.path.exists():
            return ChainVerification(valid=True, events=0)
        previous = GENESIS_HASH
        count = 0
        with self.path.open("r", encoding="utf-8") as handle:
            for number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                    stored_hash = record.pop("hash")
                except (json.JSONDecodeError, KeyError):
                    return ChainVerification(False, count, number, "unreadable line")
                if record.get("prev_hash") != previous:
                    return ChainVerification(False, count, number, "broken link to previous event")
                if _hash_record(record) != stored_hash:
                    return ChainVerification(False, count, number, "event content was modified")
                previous = stored_hash
                count += 1
        return ChainVerification(valid=True, events=count)
