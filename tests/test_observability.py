from __future__ import annotations

import json
import logging

import structlog
from fastapi import FastAPI

from smith.common import observability


def test_configure_logging_emits_json(caplog, monkeypatch):
    monkeypatch.setattr(observability, "_logging_configured", False)
    configure_logging = observability.configure_logging

    configure_logging("smith.test", "INFO")
    logger = structlog.get_logger("smith.test.logger")

    with caplog.at_level(logging.INFO):
        logger.info("structured-event", foo="bar")

    record = caplog.records[-1]
    payload = json.loads(record.message)
    assert payload["message"] == "structured-event"
    assert payload["foo"] == "bar"
    assert payload["service"] == "smith.test"


def test_parse_otlp_headers():
    value = "authorization=Bearer token, custom=abc"
    headers = observability.parse_otlp_headers(value)
    assert headers == {"authorization": "Bearer token", "custom": "abc"}


def test_instrument_fastapi_app_adds_middleware(monkeypatch):
    monkeypatch.setattr(observability, "_tracer_configured", False)
    app = FastAPI()
    observability.configure_tracing("smith.obs", None, None, 1.0)
    observability.instrument_fastapi_app(app)
    assert any(m.cls.__name__ == "OpenTelemetryMiddleware" for m in app.user_middleware)
