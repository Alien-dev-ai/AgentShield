"""Batch 41 (Batch 40 F1): a pydantic serialisation warning raised while
FastAPI serialises a route's ``response_model`` quotes the input value. It is
routed through the redacting logging set up by ``create_app()`` instead of
being written raw to stderr.

Synthetic secrets only; in-memory SQLite only.
"""

from __future__ import annotations

import json
import logging
import warnings
from collections.abc import Iterator

import pytest
from pydantic import BaseModel

from agentshield.core.security import REDACTED
from agentshield.main import create_app
from tests.conftest import RunningApp, SettingsFactory

SECRET = "SYNTH-PYDANTIC-SECRET-41c3"


class Counter(BaseModel):
    count: int


@pytest.fixture(autouse=True)
def isolated_warnings() -> Iterator[None]:
    with warnings.catch_warnings():
        # The project's pytest config turns warnings into errors; show them
        # instead, as a production process does.
        warnings.simplefilter("default")
        try:
            yield
        finally:
            logging.captureWarnings(False)
    assert getattr(warnings.showwarning, "__module__", None) != "logging"


async def test_response_model_serialisation_warning_is_redacted(
    make_settings: SettingsFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    app = create_app(make_settings(log_format="json"))

    @app.get("/_test/counter", response_model=Counter)
    async def counter() -> Counter:
        # An unvalidated model (a programming error) with a secret in it.
        return Counter.model_construct(count=f"token={SECRET}")  # type: ignore[arg-type]

    async with RunningApp(app) as client:
        capsys.readouterr()
        r = await client.get("/_test/counter")
    out, err = capsys.readouterr()
    assert r.status_code == 200
    assert SECRET not in err
    assert err == ""
    records = [json.loads(line) for line in out.splitlines() if line.startswith("{")]
    [warning] = [rec for rec in records if rec["logger"] == "py.warnings"]
    assert "PydanticSerializationUnexpectedValue" in warning["message"]
    assert f"token={REDACTED}" in warning["message"]
    for rec in records:
        if rec["logger"] != "httpx":
            assert SECRET not in json.dumps(rec)
