import logging

from app.logging_config import configure_logging, get_logger, get_memory_handler, redact, register_sensitive_value


def test_redacts_secrets():
    assert "hunter2" not in redact("login password=hunter2 ok")
    assert "abc123" not in redact("token: abc123")
    assert "xyz" not in redact("Authorization: Bearer xyz")


def test_masks_registered_serial():
    register_sensitive_value("ZY22ABCDEF")
    assert redact("device ZY22ABCDEF ready") == "device ZY••••••EF ready"


def test_child_logger_records_are_redacted_and_formatted(tmp_path):
    log_file = tmp_path / "app.log"
    configure_logging("DEBUG", log_file, console=False)
    register_sensitive_value("SERIAL998877")
    get_logger("adb").warning("Device SERIAL998877 password=secret")
    for handler in logging.getLogger("lms").handlers:
        handler.flush()
    content = log_file.read_text()
    assert "SERIAL998877" not in content and "secret" not in content
    assert " WARN Device SE" in content
    entries = get_memory_handler().entries(min_level="WARN")
    assert entries[-1]["level"] == "WARN"
    assert "SERIAL998877" not in entries[-1]["message"]


def test_memory_handler_since_and_level(tmp_path):
    configure_logging("DEBUG", None, console=False)
    log = get_logger("t")
    log.info("first")
    last = get_memory_handler().entries()[-1]["id"]
    log.debug("second")
    log.error("third")
    newer = get_memory_handler().entries(since=last)
    assert [e["message"] for e in newer] == ["second", "third"]
    assert [e["message"] for e in get_memory_handler().entries(since=last, min_level="ERROR")] == ["third"]


def test_configure_logging_is_idempotent():
    configure_logging("INFO", None, console=True)
    configure_logging("INFO", None, console=True)
    assert len(logging.getLogger("lms").handlers) == 2
