"""Golden tests for RBAC policy loading and permissions."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.nimbus.control_plane.identity_store import (
    RBACPolicy,
    load_rbac_policy,
    upsert_programs,
    get_permissions_for_roles,
    identity_metadata,
)
from tests.utils.database import temp_session


@pytest.mark.asyncio
async def test_load_rbac_policy_and_permissions(tmp_path: Path):
    """Ensure RBAC policies are loaded and enforced as expected."""
    policy_file = tmp_path / "rbac.yaml"
    policy_file.write_text(
        """
programs:
  eval:
    description: Evaluation workloads
    roles:
      admin:
        permissions:
          - eval:read
          - eval:write
      auditor:
        permissions:
          - eval:read
""",
        encoding="utf-8",
    )

    policy = load_rbac_policy(policy_file)
    assert policy.programs["eval"]["description"] == "Evaluation workloads"

    async with temp_session(identity_metadata) as session:
        await upsert_programs(session, policy)
        await session.commit()

        perms = await get_permissions_for_roles(session, program_id="eval", roles=["admin"])
        assert set(perms) == {"eval:read", "eval:write"}

        combined = await get_permissions_for_roles(session, program_id="eval", roles=["admin", "auditor"])
        assert combined == ["eval:read", "eval:write"]

        empty = await get_permissions_for_roles(session, program_id="eval", roles=["unknown"])
        assert empty == []


def test_load_missing_policy(tmp_path: Path):
    """Missing policy files should produce empty program sets."""
    policy = load_rbac_policy(tmp_path / "missing.yaml")
    assert policy.programs == {}
