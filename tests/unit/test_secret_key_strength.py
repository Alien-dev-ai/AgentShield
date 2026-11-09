"""Batch 9 (L4): production secret-key strength.

Weak keys (placeholders, repeated patterns, sequences, low variety) are
rejected in production only; random keys are accepted; errors never reveal
the key; ``create_app`` and revalidation cannot be bypassed.
"""

from __future__ import annotations

import base64
import random
import time
import uuid
from typing import Any

import pytest
from pydantic import SecretStr, ValidationError

from agentshield.core.config import (
    KEY_GENERATION_COMMAND,
    MIN_SECRET_KEY_LENGTH,
    WEAK_SECRET_KEY_MESSAGE,
    ConfigurationError,
    Environment,
    Settings,
    load_settings,
    revalidate_settings,
    secret_key_problem,
)
from agentshield.main import create_app
from tests.conftest import PRODUCTION_HOST, STRONG_SECRET, SettingsFactory, sqlite_memory_factory

PG_URL = "postgresql+asyncpg://agentshield@db.example.com:5432/agentshield"

WEAK_KEYS = {
    # Repeated characters and repeated units
    "single_char": "a" * 32,
    "previous_test_fixture": "x" * 48,
    "changeme_x4": "changeme" * 4,
    "two_char_unit": "ab" * 16,
    "unit_with_partial_tail": "abc123" * 6 + "ab",
    "digits_unit": "1234" * 8,
    # Placeholder / default / example text
    "changeme_plus_random": "changeme-9f8Kq2Lm4Xz7Wv1Rt5Yp3Nb6",
    "secret_in_key": "my-Super-SECRET-value-0193857264",
    "password_in_key": "Password-but-long-enough-9182736450",
    "example_key": "example-key-4b9f1c7e2d8a6f3b5c0e9d1a",
    "django_insecure": "django-insecure-w8#k2!q9z@r4m7v1x3b6n5c0",
    "your_key_here": "your-default-key-here-please-replace-it",
    "insecure_dev": "insecure-dev-secret-key-do-not-use-in-prod",
    "dev_segment": "dev-Zr8Kc3Lm9Qp2Wx7Vb4Nt6Hy1Js5Gd0F",
    "test_segment": "test_4f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c",
    "local_segment": "Q9w2E7r4T1y8U3i6O0p5A2s9D4f7G1h3.local",
    "qwerty_word": "Qwerty-Kc3Lm9Qp2Wx7Vb4Nt6Hy1Js5Gd0F",
    # Sequences and keyboard walks
    "alphabet_digits": "abcdefghijklmnopqrstuvwxyz012345",
    "reverse_alphabet": "zyxwvutsrqponmlkjihgfedcba987654",
    "alphabet_prefix": "abcdefghijk" + "Zr8Kc3Lm9Qp2Wx7Vb4Nt6",
    "keyboard_row": "asdfghjkl-Zr8Kc3Lm9Qp2Wx7Vb4Nt6Hy",
    "digit_run": "Zr8Kc3Lm9Qp2W-1234567-x7Vb4Nt6Hy1",
    "doubled_alphabet": "aabbccddeeffgghhiijjkkllmmnnoopp",
    "every_other_letter": "acegikmoqsuwy02468acegikmoqsuwy0",
    "letter_digit_alternation": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
    # Low variety
    "few_distinct": "1111111122222222333333334444444455",
    "one_dominant_char": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1b2c3d4e5f",
    "two_chars_mixed": "abbaabababbbaabbabaababbbaabbaab",
}

# Real-looking random keys (fixed, so the test is deterministic).
VALID_KEYS = {
    "token_urlsafe_48": STRONG_SECRET,
    "token_urlsafe_32_chars": "Jm4xQ8vT2nR7kW1pZ5cL9bH3sD6fG0yE",
    "token_hex_16": "9b1f4c7e2a8d6053fe1b9c4a7d2e8f60",
    "base64_padded": "pQ3m8ZkR1vT6xW9nB2cL5hJ7sD0fG4yE+Ua/oIe=",
    "uuid4_hex": "3f2b8c1e9d4a47e6b0c5a8f17d2e9b46",
    "with_symbols": "w8#K2!q9Z@r4M7v1X3b6N5c0$Lp^Ty&Hu3",
    "long_unicode": "Ωmé7Zr8Kc3Lm9Qp2Wx7Vb4Nt6Hy1Js5Gd0Füñ",
}


def _seeded_keys(fmt: str, count: int, n_bytes: int) -> list[str]:
    """Keys in the format of the secrets module, from a fixed seed (the
    secrets module itself would make the test non-deterministic)."""
    rng = random.Random(f"agentshield-batch9-{fmt}-{n_bytes}")  # noqa: S311 - test data only
    keys = []
    for _ in range(count):
        raw = rng.randbytes(n_bytes)
        if fmt == "urlsafe":
            keys.append(base64.urlsafe_b64encode(raw).rstrip(b"=").decode())
        elif fmt == "hex":
            keys.append(raw.hex())
        elif fmt == "base64":
            keys.append(base64.b64encode(raw).decode())
        else:
            keys.append(uuid.UUID(bytes=raw[:16], version=4).hex)
    return keys


def _production(**overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "environment": Environment.PRODUCTION,
        "database_url": SecretStr(PG_URL),
        "secret_key": SecretStr(STRONG_SECRET),
        "allowed_hosts": [PRODUCTION_HOST],
    }
    values.update(overrides)
    return values


def _fragments(secret: str, size: int = 8) -> list[str]:
    return [secret[i : i + size] for i in range(len(secret) - size + 1)]


# --- Rejected -------------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(WEAK_KEYS))
def test_weak_keys_are_rejected(name: str) -> None:
    key = WEAK_KEYS[name]
    assert len(key) >= MIN_SECRET_KEY_LENGTH, "weak by structure, not by length"
    assert secret_key_problem(key) == WEAK_SECRET_KEY_MESSAGE


@pytest.mark.parametrize("name", sorted(WEAK_KEYS))
def test_weak_keys_are_rejected_in_production_settings(name: str) -> None:
    with pytest.raises(ValidationError, match="secret_key is too weak"):
        Settings(**_production(secret_key=SecretStr(WEAK_KEYS[name])))


@pytest.mark.parametrize("key", ["", "short", "changeme", "x" * (MIN_SECRET_KEY_LENGTH - 1)])
def test_short_keys_keep_the_length_message(key: str) -> None:
    assert secret_key_problem(key) == (
        f"secret_key must be at least {MIN_SECRET_KEY_LENGTH} characters"
    )


def test_missing_key_is_still_required() -> None:
    with pytest.raises(ValidationError, match="secret_key is required"):
        Settings(**_production(secret_key=None))


# --- Accepted -------------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(VALID_KEYS))
def test_random_looking_keys_are_accepted(name: str) -> None:
    key = VALID_KEYS[name]
    assert secret_key_problem(key) is None
    settings = Settings(**_production(secret_key=SecretStr(key)))
    assert settings.is_production


@pytest.mark.parametrize(
    ("fmt", "n_bytes"),
    [("urlsafe", 24), ("urlsafe", 48), ("hex", 16), ("hex", 32), ("base64", 32), ("uuid", 16)],
)
def test_generated_keys_are_accepted(fmt: str, n_bytes: int) -> None:
    keys = _seeded_keys(fmt, 3_000, n_bytes)
    assert all(len(k) >= MIN_SECRET_KEY_LENGTH for k in keys)
    rejected = [k for k in keys if secret_key_problem(k)]
    assert rejected == []


def test_documented_generator_output_is_accepted() -> None:
    # The command in the error message and docs produces token_urlsafe(48).
    assert "token_urlsafe(48)" in KEY_GENERATION_COMMAND
    assert all(secret_key_problem(k) is None for k in _seeded_keys("urlsafe", 500, 48))


# --- Development and test are unchanged ----------------------------------------


@pytest.mark.parametrize("environment", [Environment.DEVELOPMENT, Environment.TEST])
@pytest.mark.parametrize("key", [None, "a" * 32, "changeme", "dev"])
def test_development_and_test_accept_any_key(
    make_settings: SettingsFactory, environment: Environment, key: str | None
) -> None:
    settings = make_settings(
        environment=environment, secret_key=SecretStr(key) if key is not None else None
    )
    assert not settings.is_production
    assert revalidate_settings(settings).secret_key == settings.secret_key


# --- Errors never reveal the key ------------------------------------------------


@pytest.mark.parametrize("name", ["changeme_plus_random", "secret_in_key", "dev_segment"])
def test_errors_never_contain_the_key(name: str) -> None:
    key = WEAK_KEYS[name]
    with pytest.raises(ValidationError) as direct:
        Settings(**_production(secret_key=SecretStr(key)))
    with pytest.raises(ConfigurationError) as loaded:
        load_settings(**_production(secret_key=SecretStr(key)))
    assert loaded.value.__cause__ is None
    texts = [str(direct.value), repr(direct.value), str(loaded.value), repr(loaded.value)]
    texts.extend(str(e) for e in direct.value.errors(include_input=False))
    for text in texts:
        for fragment in _fragments(key):
            assert fragment not in text
    assert KEY_GENERATION_COMMAND in str(loaded.value)


def test_error_message_is_fixed_for_every_weak_key() -> None:
    assert {secret_key_problem(k) for k in WEAK_KEYS.values()} == {WEAK_SECRET_KEY_MESSAGE}


# --- No bypass via copies, create_app or revalidation ---------------------------


@pytest.mark.parametrize("name", ["single_char", "changeme_x4", "alphabet_digits"])
def test_create_app_and_revalidation_reject_weak_keys(
    production_settings: Settings, name: str
) -> None:
    weak = production_settings.model_copy(update={"secret_key": SecretStr(WEAK_KEYS[name])})
    with pytest.raises(ConfigurationError, match="secret_key is too weak") as revalidated:
        revalidate_settings(weak)
    with pytest.raises(ConfigurationError, match="secret_key is too weak") as created:
        create_app(weak, database_factory=sqlite_memory_factory)
    for error in (revalidated.value, created.value):
        assert WEAK_KEYS[name] not in str(error)
        assert error.__cause__ is None


def test_model_construct_cannot_bypass() -> None:
    constructed = Settings.model_construct(
        **_production(secret_key=SecretStr(WEAK_KEYS["changeme_x4"]))
    )
    with pytest.raises(ConfigurationError, match="secret_key is too weak"):
        create_app(constructed, database_factory=sqlite_memory_factory)


def test_environment_variable_keys_are_checked(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTSHIELD_SECRET_KEY", WEAK_KEYS["insecure_dev"])
    with pytest.raises(ConfigurationError, match="secret_key is too weak") as exc:
        load_settings(**{k: v for k, v in _production().items() if k != "secret_key"})
    assert WEAK_KEYS["insecure_dev"] not in str(exc.value)


# --- Efficiency -----------------------------------------------------------------


@pytest.mark.parametrize(
    "key",
    [
        "a" * 1_000_000,
        ("q7ZrX2mVb9KcT4wLp1NyHd8sGf3JaE6uR0oPiW5tYk" * 25_000),
        VALID_KEYS["token_urlsafe_32_chars"] * 30_000,
    ],
)
def test_validation_is_linear_on_huge_keys(key: str) -> None:
    start = time.perf_counter()
    assert secret_key_problem(key) == WEAK_SECRET_KEY_MESSAGE
    assert time.perf_counter() - start < 2.0
