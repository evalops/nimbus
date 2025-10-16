"""Identity persistence and RBAC helpers for the control plane."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import secrets
from pathlib import Path
from typing import Iterable, Optional

import structlog
import yaml
from sqlalchemy import (
    Boolean,
    JSON,
    Column,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
    and_,
    delete,
    insert,
    select,
    update,
)
from sqlalchemy.sql import func
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession


LOGGER = structlog.get_logger("nimbus.control_plane.identity_store")

identity_metadata = MetaData()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


programs_table = Table(
    "programs",
    identity_metadata,
    Column("program_id", String(length=128), primary_key=True),
    Column("description", Text, nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False, default=_utc_now),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=_utc_now),
)


program_roles_table = Table(
    "program_roles",
    identity_metadata,
    Column("program_id", String(length=128), nullable=False),
    Column("role_name", String(length=128), nullable=False),
    Column("description", Text, nullable=True),
    Column("permissions", JSON, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False, default=_utc_now),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=_utc_now),
    UniqueConstraint("program_id", "role_name", name="uq_program_role"),
    ForeignKeyConstraint(["program_id"], [programs_table.c.program_id], ondelete="CASCADE"),
)


users_table = Table(
    "users",
    identity_metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("external_id", String(length=256), nullable=False, unique=True),
    Column("email", String(length=320), nullable=False),
    Column("display_name", String(length=256), nullable=True),
    Column("active", Boolean, nullable=False, default=True),
    Column("scim_id", String(length=64), unique=True, nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False, default=_utc_now),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=_utc_now),
    Column("primary_program", String(length=128), nullable=True),
    Column("metadata", JSON, nullable=True),
)
Index("ix_users_external_id", users_table.c.external_id)


user_program_roles_table = Table(
    "user_program_roles",
    identity_metadata,
    Column("user_id", Integer, nullable=False),
    Column("program_id", String(length=128), nullable=False),
    Column("role_name", String(length=128), nullable=False),
    Column("granted_at", DateTime(timezone=True), nullable=False, default=_utc_now),
    UniqueConstraint("user_id", "program_id", "role_name", name="uq_user_program_role"),
    ForeignKeyConstraint(["user_id"], [users_table.c.id], ondelete="CASCADE"),
    ForeignKeyConstraint(["program_id", "role_name"], [program_roles_table.c.program_id, program_roles_table.c.role_name], ondelete="CASCADE"),
    Index("ix_user_program", "user_id", "program_id"),
)


groups_table = Table(
    "groups",
    identity_metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("external_id", String(length=256), nullable=True, unique=True),
    Column("display_name", String(length=256), nullable=False),
    Column("program_id", String(length=128), nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False, default=_utc_now),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=_utc_now),
)


group_memberships_table = Table(
    "group_memberships",
    identity_metadata,
    Column("group_id", Integer, nullable=False),
    Column("user_id", Integer, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False, default=_utc_now),
    UniqueConstraint("group_id", "user_id", name="uq_group_membership"),
    ForeignKeyConstraint(["group_id"], [groups_table.c.id], ondelete="CASCADE"),
    ForeignKeyConstraint(["user_id"], [users_table.c.id], ondelete="CASCADE"),
)


service_accounts_table = Table(
    "service_accounts",
    identity_metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("program_id", String(length=128), nullable=False),
    Column("name", String(length=128), nullable=False),
    Column("description", Text, nullable=True),
    Column("created_by", String(length=256), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False, default=_utc_now),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=_utc_now),
    UniqueConstraint("program_id", "name", name="uq_service_account_name"),
)


service_account_tokens_table = Table(
    "service_account_tokens",
    identity_metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("service_account_id", Integer, nullable=False),
    Column("token_hash", String(length=128), nullable=False, unique=True),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False, default=_utc_now),
    Column("created_by", String(length=256), nullable=False),
    Column("last_used_at", DateTime(timezone=True), nullable=True),
    ForeignKeyConstraint(["service_account_id"], [service_accounts_table.c.id], ondelete="CASCADE"),
    Index("ix_service_account_token_hash", "token_hash", unique=True),
)


scim_sync_table = Table(
    "scim_sync_state",
    identity_metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("resource_id", String(length=64), nullable=False),
    Column("resource_type", String(length=32), nullable=False),
    Column("version", String(length=64), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=_utc_now),
    UniqueConstraint("resource_id", "resource_type", name="uq_scim_resource"),
)


@dataclass
class ProgramRole:
    program_id: str
    role_name: str
    permissions: list[str]


@dataclass
class RBACPolicy:
    programs: dict[str, dict[str, object]]


def load_rbac_policy(path: Optional[Path]) -> RBACPolicy:
    if path is None or not path.exists():
        LOGGER.warning("RBAC policy file not provided", path=str(path))
        return RBACPolicy(programs={})
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if "programs" in data and isinstance(data["programs"], dict):
        programs = data["programs"]
    else:
        programs = data
    normalized = {str(program_id): (spec or {}) for program_id, spec in programs.items()}
    return RBACPolicy(programs=normalized)


async def ensure_schema(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(identity_metadata.create_all)


async def upsert_programs(session: AsyncSession, policy: RBACPolicy) -> None:
    """Ensure programs and roles from policy exist in the database."""

    for program_id, spec in policy.programs.items():
        description = str(spec.get("description", "")) if isinstance(spec, dict) else ""
        await _upsert_program(session, program_id, description)
        roles = spec.get("roles", {}) if isinstance(spec, dict) else {}
        if not isinstance(roles, dict):
            continue
        for role_name, role_spec in roles.items():
            permissions: Iterable[str]
            role_desc = ""
            if isinstance(role_spec, dict):
                permissions = role_spec.get("permissions", [])
                role_desc = str(role_spec.get("description", ""))
            elif isinstance(role_spec, list):
                permissions = role_spec
            else:
                permissions = []
            await _upsert_program_role(session, program_id, role_name, list(permissions), role_desc)


async def _upsert_program(session: AsyncSession, program_id: str, description: str) -> None:
    now = _utc_now()
    stmt = select(programs_table.c.program_id).where(programs_table.c.program_id == program_id)
    result = await session.execute(stmt)
    if result.first():
        update_stmt = (
            update(programs_table)
            .where(programs_table.c.program_id == program_id)
            .values(description=description, updated_at=now)
        )
        await session.execute(update_stmt)
        return
    insert_stmt = insert(programs_table).values(
        program_id=program_id,
        description=description,
        created_at=now,
        updated_at=now,
    )
    await session.execute(insert_stmt)


async def _upsert_program_role(
    session: AsyncSession,
    program_id: str,
    role_name: str,
    permissions: list[str],
    description: str,
) -> None:
    now = _utc_now()
    stmt = select(program_roles_table.c.program_id).where(
        and_(
            program_roles_table.c.program_id == program_id,
            program_roles_table.c.role_name == role_name,
        )
    )
    result = await session.execute(stmt)
    payload = {
        "description": description,
        "permissions": permissions,
        "updated_at": now,
    }
    if result.first():
        update_stmt = (
            update(program_roles_table)
            .where(
                and_(
                    program_roles_table.c.program_id == program_id,
                    program_roles_table.c.role_name == role_name,
                )
            )
            .values(**payload)
        )
        await session.execute(update_stmt)
        return
    insert_stmt = insert(program_roles_table).values(
        program_id=program_id,
        role_name=role_name,
        created_at=now,
        **payload,
    )
    await session.execute(insert_stmt)


async def upsert_user(
    session: AsyncSession,
    *,
    external_id: str,
    email: str,
    display_name: Optional[str],
    active: bool,
    primary_program: Optional[str],
    metadata: Optional[dict],
    scim_id: Optional[str] = None,
) -> dict:
    now = _utc_now()
    stmt = select(users_table).where(users_table.c.external_id == external_id)
    result = await session.execute(stmt)
    existing = result.mappings().first()
    payload = {
        "email": email,
        "display_name": display_name,
        "active": active,
        "updated_at": now,
        "primary_program": primary_program,
        "metadata": metadata,
    }
    if scim_id:
        payload["scim_id"] = scim_id
    if existing:
        await session.execute(
            update(users_table)
            .where(users_table.c.id == existing["id"])
            .values(**payload)
        )
        data = {**existing, **payload}
        data["id"] = existing["id"]
        return data
    insert_payload = {
        "external_id": external_id,
        "email": email,
        "display_name": display_name,
        "active": active,
        "primary_program": primary_program,
        "metadata": metadata,
        "created_at": now,
        "updated_at": now,
        "scim_id": scim_id,
    }
    result = await session.execute(insert(users_table).values(**insert_payload).returning(users_table))
    row = result.mappings().first()
    return dict(row) if row else insert_payload


async def assign_roles(
    session: AsyncSession,
    *,
    user_id: int,
    program_id: str,
    roles: Iterable[str],
) -> None:
    now = _utc_now()
    for role in roles:
        stmt = select(user_program_roles_table.c.user_id).where(
            and_(
                user_program_roles_table.c.user_id == user_id,
                user_program_roles_table.c.program_id == program_id,
                user_program_roles_table.c.role_name == role,
            )
        )
        result = await session.execute(stmt)
        if result.first():
            continue
        await session.execute(
            insert(user_program_roles_table).values(
                user_id=user_id,
                program_id=program_id,
                role_name=role,
                granted_at=now,
            )
        )


async def replace_roles(
    session: AsyncSession,
    *,
    user_id: int,
    program_id: str,
    roles: Iterable[str],
) -> None:
    desired = {role for role in roles}
    stmt = select(user_program_roles_table.c.role_name).where(
        and_(
            user_program_roles_table.c.user_id == user_id,
            user_program_roles_table.c.program_id == program_id,
        )
    )
    result = await session.execute(stmt)
    existing = {row.role_name for row in result}
    to_remove = existing - desired
    to_add = desired - existing
    if to_remove:
        await session.execute(
            delete(user_program_roles_table).where(
                and_(
                    user_program_roles_table.c.user_id == user_id,
                    user_program_roles_table.c.program_id == program_id,
                    user_program_roles_table.c.role_name.in_(to_remove),
                )
            )
        )
    if to_add:
        await assign_roles(session, user_id=user_id, program_id=program_id, roles=to_add)


async def revoke_user(session: AsyncSession, *, user_id: int) -> None:
    await session.execute(
        update(users_table)
        .where(users_table.c.id == user_id)
        .values(active=False, updated_at=_utc_now())
    )


async def get_user_by_external_id(session: AsyncSession, external_id: str) -> Optional[dict]:
    stmt = select(users_table).where(users_table.c.external_id == external_id)
    result = await session.execute(stmt)
    row = result.mappings().first()
    return dict(row) if row else None


async def get_user_by_scim_id(session: AsyncSession, scim_id: str) -> Optional[dict]:
    stmt = select(users_table).where(users_table.c.scim_id == scim_id)
    result = await session.execute(stmt)
    row = result.mappings().first()
    return dict(row) if row else None


async def list_users(session: AsyncSession, *, start: int, count: int) -> tuple[int, list[dict]]:
    total_result = await session.execute(select(func.count()).select_from(users_table))
    total = total_result.scalar_one()
    stmt = (
        select(users_table)
        .order_by(users_table.c.id)
        .offset(max(0, start - 1))
        .limit(count)
    )
    result = await session.execute(stmt)
    rows = [dict(row) for row in result.mappings()]
    return total, rows


async def get_user_roles(session: AsyncSession, *, user_id: int, program_id: str) -> list[str]:
    stmt = select(user_program_roles_table.c.role_name).where(
        and_(
            user_program_roles_table.c.user_id == user_id,
            user_program_roles_table.c.program_id == program_id,
        )
    )
    result = await session.execute(stmt)
    return [row.role_name for row in result]


async def get_permissions_for_roles(
    session: AsyncSession,
    *,
    program_id: str,
    roles: Iterable[str],
) -> list[str]:
    stmt = select(program_roles_table.c.permissions).where(
        and_(
            program_roles_table.c.program_id == program_id,
            program_roles_table.c.role_name.in_(list(roles)),
        )
    )
    result = await session.execute(stmt)
    permissions: list[str] = []
    for row in result:
        perms = row.permissions or []
        if isinstance(perms, list):
            permissions.extend(perms)
        elif isinstance(perms, str):
            try:
                decoded = json.loads(perms)
                if isinstance(decoded, list):
                    permissions.extend(decoded)
            except json.JSONDecodeError:
                permissions.append(perms)
    return sorted(set(permissions))


async def create_service_account(
    session: AsyncSession,
    *,
    program_id: str,
    name: str,
    description: Optional[str],
    created_by: str,
) -> dict:
    now = _utc_now()
    result = await session.execute(
        insert(service_accounts_table)
        .values(
            program_id=program_id,
            name=name,
            description=description,
            created_by=created_by,
            created_at=now,
            updated_at=now,
        )
        .returning(service_accounts_table)
    )
    row = result.mappings().first()
    return dict(row) if row else {}


async def get_service_account_by_name(
    session: AsyncSession,
    *,
    program_id: str,
    name: str,
) -> Optional[dict]:
    stmt = select(service_accounts_table).where(
        and_(
            service_accounts_table.c.program_id == program_id,
            service_accounts_table.c.name == name,
        )
    )
    result = await session.execute(stmt)
    row = result.mappings().first()
    return dict(row) if row else None


async def get_service_account(
    session: AsyncSession,
    *,
    service_account_id: int,
) -> Optional[dict]:
    stmt = select(service_accounts_table).where(service_accounts_table.c.id == service_account_id)
    result = await session.execute(stmt)
    row = result.mappings().first()
    return dict(row) if row else None


async def mint_service_account_token(
    session: AsyncSession,
    *,
    service_account_id: int,
    ttl_seconds: int,
    created_by: str,
) -> tuple[str, dict]:
    now = _utc_now()
    expires_at = now + timedelta(seconds=ttl_seconds)
    token = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    result = await session.execute(
        insert(service_account_tokens_table)
        .values(
            service_account_id=service_account_id,
            token_hash=token_hash,
            expires_at=expires_at,
            created_at=now,
            created_by=created_by,
        )
        .returning(service_account_tokens_table)
    )
    row = result.mappings().first()
    return token, dict(row) if row else {}


async def validate_service_account_token(
    session: AsyncSession,
    token: str,
) -> Optional[dict]:
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    stmt = (
        select(
            service_account_tokens_table,
            service_accounts_table,
        )
        .join(service_accounts_table, service_accounts_table.c.id == service_account_tokens_table.c.service_account_id)
        .where(service_account_tokens_table.c.token_hash == token_hash)
    )
    result = await session.execute(stmt)
    row = result.mappings().first()
    if not row:
        return None
    token_record = dict(row[service_account_tokens_table])
    if token_record["expires_at"] <= _utc_now():
        return None
    await session.execute(
        update(service_account_tokens_table)
        .where(service_account_tokens_table.c.id == token_record["id"])
        .values(last_used_at=_utc_now())
    )
    account = dict(row[service_accounts_table])
    token_record["service_account"] = account
    return token_record


async def list_service_account_tokens(
    session: AsyncSession,
    *,
    service_account_id: int,
) -> list[dict]:
    stmt = select(service_account_tokens_table).where(
        service_account_tokens_table.c.service_account_id == service_account_id
    )
    result = await session.execute(stmt)
    return [dict(row) for row in result.mappings()]


async def get_service_account_token(
    session: AsyncSession,
    *,
    token_id: int,
) -> Optional[dict]:
    stmt = select(service_account_tokens_table).where(service_account_tokens_table.c.id == token_id)
    result = await session.execute(stmt)
    row = result.mappings().first()
    return dict(row) if row else None


async def revoke_service_account_token(session: AsyncSession, *, token_id: int) -> None:
    await session.execute(
        delete(service_account_tokens_table).where(service_account_tokens_table.c.id == token_id)
    )


async def deactivate_service_account(session: AsyncSession, *, service_account_id: int) -> None:
    await session.execute(
        delete(service_accounts_table).where(service_accounts_table.c.id == service_account_id)
    )


async def grant_program_roles_to_service_account(
    session: AsyncSession,
    *,
    service_account_id: int,
    roles: Iterable[str],
) -> None:
    account_stmt = select(service_accounts_table).where(service_accounts_table.c.id == service_account_id)
    result = await session.execute(account_stmt)
    account = result.mappings().first()
    if not account:
        raise ValueError("Service account not found")
    program_id = account["program_id"]
    await _ensure_program_roles_exist(session, program_id, roles)


async def _ensure_program_roles_exist(session: AsyncSession, program_id: str, roles: Iterable[str]) -> None:
    roles = list(set(roles))
    if not roles:
        return
    stmt = select(program_roles_table.c.role_name).where(
        and_(
            program_roles_table.c.program_id == program_id,
            program_roles_table.c.role_name.in_(roles),
        )
    )
    result = await session.execute(stmt)
    existing = {row.role_name for row in result}
    missing = set(roles) - existing
    if missing:
        raise ValueError(f"Missing RBAC roles for program {program_id}: {', '.join(sorted(missing))}")


async def get_program_permissions_for_service_account(
    session: AsyncSession,
    *,
    service_account_id: int,
) -> list[str]:
    stmt = select(service_accounts_table).where(service_accounts_table.c.id == service_account_id)
    result = await session.execute(stmt)
    account = result.mappings().first()
    if not account:
        return []
    program_id = account["program_id"]
    # Service accounts inherit permissions by roles stored in metadata
    metadata = account.get("description") or ""
    try:
        decoded = json.loads(metadata)
    except json.JSONDecodeError:
        decoded = {}
    roles = decoded.get("roles", []) if isinstance(decoded, dict) else []
    if not roles:
        return []
    return await get_permissions_for_roles(session, program_id=program_id, roles=roles)


async def update_service_account_roles(
    session: AsyncSession,
    *,
    service_account_id: int,
    program_id: str,
    roles: Iterable[str],
    description: Optional[str] = None,
) -> None:
    await _ensure_program_roles_exist(session, program_id, roles)
    payload = {"roles": sorted(set(roles))}
    if description:
        payload["description"] = description
    stmt = (
        update(service_accounts_table)
        .where(service_accounts_table.c.id == service_account_id)
        .values(
            description=json.dumps(payload),
            updated_at=_utc_now(),
        )
    )
    await session.execute(stmt)


async def list_program_roles(session: AsyncSession, program_id: str) -> list[dict]:
    stmt = select(program_roles_table).where(program_roles_table.c.program_id == program_id)
    result = await session.execute(stmt)
    return [dict(row) for row in result.mappings()]


async def list_user_program_roles(session: AsyncSession, user_id: int) -> list[dict]:
    stmt = select(user_program_roles_table).where(user_program_roles_table.c.user_id == user_id)
    result = await session.execute(stmt)
    return [dict(row) for row in result.mappings()]
