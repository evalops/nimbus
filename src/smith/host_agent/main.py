"""Command-line entrypoint for running the Smith host agent."""

from __future__ import annotations

import asyncio
import logging

from ..common.settings import HostAgentSettings
from .agent import HostAgent

logging.basicConfig(level=logging.INFO)


async def main() -> None:
    settings = HostAgentSettings()
    agent = HostAgent(settings)
    try:
        await agent.run()
    finally:
        await agent.stop()


if __name__ == "__main__":
    asyncio.run(main())
