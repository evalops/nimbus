"""Shared observability utilities for Nimbus services."""

from __future__ import annotations

import logging
from typing import Dict, Optional

import structlog
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.asgi import OpenTelemetryMiddleware
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
try:  # pragma: no cover - optional dependency
    from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
except ModuleNotFoundError:  # pragma: no cover - fallback when extra not installed
    HTTPXClientInstrumentor = None  # type: ignore[assignment]
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.sdk.trace.sampling import TraceIdRatioBased
from structlog.contextvars import bind_contextvars


_logging_configured = False
_tracer_configured = False
_httpx_instrumented = False


def _log_level(level: str | int | None) -> int:
    if isinstance(level, int):
        return level
    if isinstance(level, str):
        normalized = level.strip().upper()
        numeric = logging.getLevelName(normalized)
        if isinstance(numeric, int):
            return numeric
    return logging.INFO


def configure_logging(service_name: str, level: str | int | None = None) -> None:
    """Configure structlog for JSON structured logging."""

    global _logging_configured
    numeric_level = _log_level(level)
    if not _logging_configured:
        logging.basicConfig(level=numeric_level, format="%(message)s")
        _logging_configured = True
    else:
        logging.getLogger().setLevel(numeric_level)

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.dict_tracebacks,
            structlog.processors.EventRenamer("message"),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(numeric_level),
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )
    bind_contextvars(service=service_name)


def parse_otlp_headers(headers: str | None) -> Dict[str, str]:
    if not headers:
        return {}
    result: Dict[str, str] = {}
    for item in headers.split(","):
        if not item.strip():
            continue
        key, _, value = item.partition("=")
        if key and value:
            result[key.strip()] = value.strip()
    return result


def configure_tracing(
    service_name: str,
    endpoint: Optional[str] = None,
    headers: Optional[str] = None,
    sampler_ratio: float = 1.0,
) -> None:
    """Configure OpenTelemetry tracing for the given service."""

    global _tracer_configured
    if _tracer_configured:
        return

    current_provider = trace.get_tracer_provider()
    if isinstance(current_provider, TracerProvider):
        _tracer_configured = True
        return

    resource = Resource.create({"service.name": service_name})
    sampler_ratio = max(0.0, min(1.0, sampler_ratio))
    provider = TracerProvider(resource=resource, sampler=TraceIdRatioBased(sampler_ratio))

    if endpoint:
        exporter = OTLPSpanExporter(endpoint=endpoint, headers=parse_otlp_headers(headers))
        processor = BatchSpanProcessor(exporter)
    else:
        exporter = InMemorySpanExporter()
        processor = SimpleSpanProcessor(exporter)

    provider.add_span_processor(processor)
    trace.set_tracer_provider(provider)
    _tracer_configured = True

    global _httpx_instrumented
    if not _httpx_instrumented and HTTPXClientInstrumentor is not None:
        HTTPXClientInstrumentor().instrument()
        _httpx_instrumented = True


def instrument_fastapi_app(app) -> None:
    """Attach OpenTelemetry instrumentation to a FastAPI app."""

    FastAPIInstrumentor.instrument_app(app, tracer_provider=trace.get_tracer_provider())
    if not any(getattr(m.cls, "__name__", "") == "OpenTelemetryMiddleware" for m in app.user_middleware):
        app.add_middleware(OpenTelemetryMiddleware, tracer_provider=trace.get_tracer_provider())
