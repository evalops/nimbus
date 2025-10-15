"""Command-line entrypoint for running the Smith host agent."""

from __future__ import annotations

import asyncio

from ..common.observability import configure_logging, configure_tracing
from ..common.settings import HostAgentSettings
from .agent import HostAgent


async def main() -> None:
    settings = HostAgentSettings()
    configure_logging("smith.host_agent", settings.log_level)
    configure_tracing(
        service_name="smith.host_agent",
        endpoint=settings.otel_exporter_endpoint,
        headers=settings.otel_exporter_headers,
        sampler_ratio=settings.otel_sampler_ratio,
    )
    agent = HostAgent(settings)
    try:
        await agent.run()
    finally:
        await agent.stop()


if __name__ == "__main__":
    asyncio.run(main())
