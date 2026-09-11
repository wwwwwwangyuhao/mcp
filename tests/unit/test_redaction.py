from personal_linux_mcp.security.redaction import redact


def test_redacts_common_secret_forms():
    text = "token=abc password=hunter2 Authorization: Bearer xyz"
    redacted = redact(text)
    assert "abc" not in redacted
    assert "hunter2" not in redacted
    assert "xyz" not in redacted
    assert redacted.count("[REDACTED]") == 3
