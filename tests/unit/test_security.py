from __future__ import annotations

import pytest

from agentshield.core.security import REDACTED, is_sensitive_key, redact, redact_text


@pytest.mark.parametrize(
    "key",
    [
        "password",
        "DB_PASSWORD",
        "api_key",
        "X-Api-Key",
        "apiKey",
        "Authorization",
        "access_token",
        "client_secret",
        "Cookie",
        "private-key",
        "database_url",
        "dsn",
    ],
)
def test_sensitive_keys(key: str) -> None:
    assert is_sensitive_key(key)


@pytest.mark.parametrize("key", ["username", "path", "status", "method", "request_id"])
def test_non_sensitive_keys(key: str) -> None:
    assert not is_sensitive_key(key)


@pytest.mark.parametrize(
    ("text", "leaked"),
    [
        ("connect postgresql+asyncpg://admin:s3cr3t@db:5432/x", "s3cr3t"),
        ("Authorization: Bearer abc.def.ghi", "abc.def.ghi"),
        ("header basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
        ("password=hunter2&user=bob", "hunter2"),
        ('{"api_key": "sk-live-123"}', "sk-live-123"),
        ("client_secret: topsecretvalue", "topsecretvalue"),
        ("X-Api-Key=abc123", "abc123"),
    ],
)
def test_redact_text_masks_credentials(text: str, leaked: str) -> None:
    out = redact_text(text)
    assert leaked not in out
    assert REDACTED in out


def test_redact_text_keeps_safe_text() -> None:
    text = "GET /health/ready 200 in 3ms user=bob"
    assert redact_text(text) == text


def test_redact_text_keeps_url_username_and_host() -> None:
    out = redact_text("postgresql://admin:pw@db.internal/x")
    assert out == f"postgresql://admin:{REDACTED}@db.internal/x"


def test_redact_nested_structures() -> None:
    data = {
        "user": "bob",
        "password": "hunter2",
        "headers": {"Authorization": "Bearer x", "Accept": "json"},
        "items": [{"token": "t1"}, "dsn postgresql://u:pw@h/db"],
        "count": 3,
    }
    out = redact(data)
    assert out["user"] == "bob"
    assert out["password"] == REDACTED
    assert out["headers"] == {"Authorization": REDACTED, "Accept": "json"}
    assert out["items"][0] == {"token": REDACTED}
    assert "pw" not in out["items"][1]
    assert out["count"] == 3
    assert data["password"] == "hunter2"  # input not mutated


def test_redact_depth_limit() -> None:
    deep: dict[str, object] = {}
    node = deep
    for _ in range(20):
        child: dict[str, object] = {}
        node["n"] = child
        node = child
    out = redact(deep)
    for _ in range(9):
        out = out["n"]
    assert out == REDACTED
