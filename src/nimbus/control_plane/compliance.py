"""Compliance control mapping and export logging."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Optional

import structlog
import yaml
from sqlalchemy import (
    Column,
    DateTime,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    insert,
    select,
    delete,
)
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession


LOGGER = structlog.get_logger("nimbus.control_plane.compliance")

metadata = MetaData()


export_events_table = Table(
    "compliance_export_events",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("program_id", String(length=128), nullable=False),
    Column("actor", String(length=256), nullable=False),
    Column("data_classification", String(length=128), nullable=False),
    Column("destination_region", String(length=128), nullable=False),
    Column("justification", Text, nullable=False),
    Column("recorded_at", DateTime(timezone=True), nullable=False),
)


@dataclass
class ControlMatrix:
    raw: dict

    def controls_for(self, framework: str) -> dict:
        return self.raw.get(framework.lower(), {})


def load_control_matrix(path: Optional[Path]) -> ControlMatrix:
    if path is None or not path.exists():
        LOGGER.warning("Compliance matrix missing", path=str(path))
        return ControlMatrix(raw={})
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    normalized = {str(key).lower(): value for key, value in data.items()}
    return ControlMatrix(raw=normalized)


async def ensure_schema(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(metadata.create_all)


async def record_export_event(
    session: AsyncSession,
    *,
    program_id: str,
    actor: str,
    data_classification: str,
    destination_region: str,
    justification: str,
) -> dict:
    now = datetime.now(timezone.utc)
    result = await session.execute(
        insert(export_events_table)
        .values(
            program_id=program_id,
            actor=actor,
            data_classification=data_classification,
            destination_region=destination_region,
            justification=justification,
            recorded_at=now,
        )
        .returning(export_events_table)
    )
    row = result.mappings().first()
    return dict(row) if row else {}


async def prune_export_events(
    session: AsyncSession,
    *,
    retention_days: int,
) -> int:
    cutoff = datetime.now(timezone.utc) - timedelta(days=max(1, retention_days))
    stmt = delete(export_events_table).where(export_events_table.c.recorded_at < cutoff)
    result = await session.execute(stmt)
    return result.rowcount or 0


async def list_export_events(
    session: AsyncSession,
    *,
    program_id: Optional[str] = None,
) -> list[dict]:
    stmt = select(export_events_table).order_by(export_events_table.c.recorded_at.desc())
    if program_id:
        stmt = stmt.where(export_events_table.c.program_id == program_id)
    result = await session.execute(stmt)
    return [dict(row) for row in result.mappings()]


def enforce_residency(region: str, permitted_regions: Iterable[str]) -> None:
    regions = {item.lower() for item in permitted_regions}
    if regions and region.lower() not in regions:
        raise PermissionError(f"Region {region} not permitted for ITAR/EAR data")
