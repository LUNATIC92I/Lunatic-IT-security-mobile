import json

from app.core.audit_logger import AuditLogger


def test_chain_valid(tmp_path):
    audit = AuditLogger(tmp_path / "audit.jsonl")
    audit.record("device_detected", serial="0A1B2C3D4E", model="Pixel 8")
    audit.record("flash_started", level="warn")
    result = audit.verify()
    assert result.valid and result.events == 2
    events = audit.read()
    assert events[0]["details"]["serial"] == "0A••••••4E"
    assert events[1]["prev_hash"] == events[0]["hash"]


def test_secrets_are_dropped(tmp_path):
    audit = AuditLogger(tmp_path / "audit.jsonl")
    audit.record("x", password="p", nested={"api_key": "k", "ok": 1})
    raw = (tmp_path / "audit.jsonl").read_text()
    assert '"p"' not in raw and '"k"' not in raw and "[REDACTED]" in raw


def test_tampering_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = AuditLogger(path)
    for i in range(3):
        audit.record("event", index=i)
    lines = path.read_text().splitlines()
    record = json.loads(lines[1])
    record["details"]["index"] = 99
    lines[1] = json.dumps(record)
    path.write_text("\n".join(lines) + "\n")
    result = AuditLogger(path).verify()
    assert not result.valid and result.first_invalid_line == 2


def test_deletion_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = AuditLogger(path)
    for i in range(3):
        audit.record("event", index=i)
    lines = path.read_text().splitlines()
    path.write_text("\n".join([lines[0], lines[2]]) + "\n")
    assert not AuditLogger(path).verify().valid


def test_chain_continues_across_instances(tmp_path):
    path = tmp_path / "audit.jsonl"
    AuditLogger(path).record("a")
    AuditLogger(path).record("b")
    assert AuditLogger(path).verify().events == 2


def test_corrupted_tail_keeps_chain_broken(tmp_path):
    path = tmp_path / "audit.jsonl"
    AuditLogger(path).record("a")
    with path.open("a") as handle:
        handle.write("not json\n")
    AuditLogger(path).record("b")
    result = AuditLogger(path).verify()
    assert not result.valid and result.first_invalid_line == 2
