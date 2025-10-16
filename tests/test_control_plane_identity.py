from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import httpx
import jwt
import pytest

from nimbus.common.security import mint_agent_token
from nimbus.control_plane.app import (
    AppState,
    RateLimiter,
    _decode_session_token,
    _mint_session_token,
    create_app,
)
from nimbus.control_plane.identity_store import RBACPolicy


class FakeRedis:
    async def aclose(self) -> None:
        return None


class FakeSamlAuthenticator:
    next_assertion: dict[str, object] = {
        "name_id": "user-1",
        "attributes": {},
        "session_info": {},
    }

    def __init__(self, *_args, **_kwargs) -> None:
        pass

    def metadata_xml(self) -> str:
        return "<EntityDescriptor/>"

    def prepare_redirect(self, relay_state: str | None = None) -> tuple[str, dict[str, str]]:
        return "https://idp.example.com/login", {"SAMLRequest": "request", "RelayState": relay_state or ""}

    def parse_assertion(self, _saml_response: str) -> dict[str, object]:
        return FakeSamlAuthenticator.next_assertion


async def _create_client(app):
    lifespan = app.router.lifespan_context(app)
    await lifespan.__aenter__()
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver")
    return client, lifespan


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def control_plane_app(monkeypatch, tmp_path: Path):
    db_path = tmp_path / "control.db"
    metadata_path = tmp_path / "idp.xml"
    metadata_path.write_text("<EntityDescriptor/>", encoding="utf-8")
    program_policy_path = tmp_path / "programs.yaml"
    program_policy_path.write_text(
        """
programs:
  orion:
    description: "Test program"
    roles:
      operator:
        permissions:
          - iam.manage
          - iam.token
          - compliance.view
          - compliance.export
""".strip(),
        encoding="utf-8",
    )
    compliance_path = tmp_path / "controls.yaml"
    compliance_path.write_text(
        """
nist:
  ac-2: Managed accounts
""".strip(),
        encoding="utf-8",
    )
    egress_policy_path = tmp_path / "egress.yaml"
    egress_policy_path.write_text(
        """
policies:
  - effect: allow
    pattern: '^https://registry\\.internal\\.example.com'
  - effect: deny
    pattern: '^https://'
""".strip(),
        encoding="utf-8",
    )

    env = {
        "NIMBUS_GITHUB_APP_ID": "1",
        "NIMBUS_GITHUB_APP_PRIVATE_KEY": "test",
        "NIMBUS_GITHUB_APP_INSTALLATION_ID": "1",
        "NIMBUS_GITHUB_WEBHOOK_SECRET": "webhook",
        "NIMBUS_REDIS_URL": "redis://test",
        "NIMBUS_DATABASE_URL": f"sqlite+aiosqlite:///{db_path}",
        "NIMBUS_JWT_SECRET": "jwt-secret",
        "NIMBUS_PUBLIC_BASE_URL": "http://localhost",
        "NIMBUS_CACHE_TOKEN_TTL": "3600",
        "NIMBUS_CACHE_SHARED_SECRET": "cache-secret",
        "NIMBUS_AGENT_TOKEN_SECRET": "agent-secret",
        "NIMBUS_AGENT_TOKEN_RATE_LIMIT": "10",
        "NIMBUS_AGENT_TOKEN_RATE_INTERVAL": "60",
        "NIMBUS_SSH_PORT_START": "23000",
        "NIMBUS_SSH_PORT_END": "23010",
        "NIMBUS_SSH_SESSION_TTL": "600",
        "NIMBUS_OFFLINE_MODE": "true",
        "NIMBUS_ALLOWED_ARTIFACT_REGISTRIES": "[\"registry.internal.example.com\"]",
        "NIMBUS_METADATA_DENYLIST": "[\"169.254.169.254\"]",
        "NIMBUS_EGRESS_POLICY_PACK": str(egress_policy_path),
        "NIMBUS_PROGRAM_POLICY_PATH": str(program_policy_path),
        "NIMBUS_COMPLIANCE_MATRIX": str(compliance_path),
        "NIMBUS_SCIM_TOKEN": "scim-token",
        "NIMBUS_SSO_SESSION_SECRET": "session-secret",
        "NIMBUS_SAML_SP_ENTITY_ID": "urn:test:nimbus",
        "NIMBUS_SAML_ACS_URL": "http://localhost/sso/acs",
        "NIMBUS_SAML_IDP_METADATA": str(metadata_path),
        "NIMBUS_SERVICE_ACCOUNT_TTL": "900",
        "NIMBUS_ITAR_REGIONS": "[\"us\"]",
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    monkeypatch.setattr("nimbus.control_plane.app.redis_from_url", lambda *_args, **_kwargs: FakeRedis())
    monkeypatch.setattr("nimbus.control_plane.app.SamlAuthenticator", FakeSamlAuthenticator)

    app = create_app()
    client, lifespan = await _create_client(app)

    try:
        state: AppState = app.state.container  # type: ignore[attr-defined]
        yield app, client, state
    finally:
        await client.aclose()
        await lifespan.__aexit__(None, None, None)


@pytest.mark.anyio("asyncio")
async def test_saml_flow_mints_session_token(control_plane_app) -> None:
    app, client, state = control_plane_app

    FakeSamlAuthenticator.next_assertion = {
        "name_id": "user-42",
        "attributes": {
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": ["astro@example.com"],
            "nimbusProgram": ["orion"],
            "nimbusRoles": ["operator"],
        },
        "session_info": {},
    }

    response = await client.post("/sso/acs", data={"SAMLResponse": "dummy"})
    assert response.status_code == 200
    payload = response.json()
    token = payload["token"]
    decoded = _decode_session_token(state.session_secret, token)
    assert decoded is not None
    assert decoded["email"] == "astro@example.com"
    assert decoded["roles"]["orion"] == ["operator"]


@pytest.mark.anyio("asyncio")
async def test_scim_user_lifecycle(control_plane_app) -> None:
    app, client, state = control_plane_app
    headers = {"Authorization": "Bearer scim-token"}

    create_resp = await client.post(
        "/scim/v2/Users",
        headers=headers,
        json={
            "externalId": "astro-1",
            "userName": "astro@example.com",
            "name": {"formatted": "Astronaut"},
            "NimbusProgram": "orion",
            "NimbusRoles": ["operator"],
        },
    )
    assert create_resp.status_code == 201
    scim_id = create_resp.json()["id"]

    patch_resp = await client.patch(
        f"/scim/v2/Users/{scim_id}",
        headers=headers,
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [
                {"op": "Replace", "path": "active", "value": False},
                {"op": "Replace", "path": "roles", "value": ["operator"]},
            ],
        },
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["active"] is False

    list_resp = await client.get("/scim/v2/Users", headers=headers)
    assert list_resp.status_code == 200
    assert list_resp.json()["totalResults"] == 1

    delete_resp = await client.delete(f"/scim/v2/Users/{scim_id}", headers=headers)
    assert delete_resp.status_code == 204


@pytest.mark.anyio("asyncio")
async def test_service_account_token_flow(control_plane_app) -> None:
    app, client, state = control_plane_app

    session_token = _mint_session_token(
        state.session_secret,
        subject="admin-user",
        email="admin@example.com",
        program_roles={"orion": ["operator"]},
    )
    headers = {"Authorization": f"Bearer {session_token}"}

    create_resp = await client.post(
        "/api/programs/orion/service-accounts",
        headers=headers,
        json={"name": "ci-bot", "description": "CI automation", "roles": ["operator"]},
    )
    assert create_resp.status_code == 201
    account_id = create_resp.json()["service_account"]["id"]

    token_resp = await client.post(
        f"/api/service-accounts/{account_id}/tokens",
        headers=headers,
        json={"ttl_seconds": 600},
    )
    assert token_resp.status_code == 201
    issued_token = token_resp.json()["token"]
    assert isinstance(issued_token, str) and issued_token

    list_resp = await client.get(f"/api/service-accounts/{account_id}/tokens", headers=headers)
    assert list_resp.status_code == 200
    tokens = list_resp.json()["tokens"]
    assert len(tokens) == 1
    token_id = tokens[0]["id"]

    revoke_resp = await client.delete(f"/api/service-account-tokens/{token_id}", headers=headers)
    assert revoke_resp.status_code == 204


@pytest.mark.anyio("asyncio")
async def test_compliance_export_logging(control_plane_app) -> None:
    app, client, state = control_plane_app

    session_token = _mint_session_token(
        state.session_secret,
        subject="auditor",
        email="auditor@example.com",
        program_roles={"orion": ["operator"]},
    )
    headers = {"Authorization": f"Bearer {session_token}"}

    export_resp = await client.post(
        "/api/compliance/export-log",
        headers=headers,
        json={
            "program_id": "orion",
            "data_classification": "ITAR",
            "destination_region": "us",
            "justification": "Mission simulation",
        },
    )
    assert export_resp.status_code == 201

    list_resp = await client.get(
        "/api/programs/orion/compliance/export-log",
        headers=headers,
    )
    assert list_resp.status_code == 200
    events = list_resp.json()["events"]
    assert len(events) == 1
    assert events[0]["data_classification"] == "ITAR"


@pytest.mark.anyio("asyncio")
async def test_authorize_program_request_allows_admin_token(control_plane_app) -> None:
    app, client, state = control_plane_app

    now = datetime.now(timezone.utc)
    admin_token = mint_agent_token(
        agent_id="admin",
        secret="jwt-secret",
        ttl_seconds=600,
    )
    headers = {"Authorization": f"Bearer {admin_token}"}

    resp = await client.get(
        "/api/compliance/matrix",
        headers=headers,
    )
    assert resp.status_code == 200
    assert "controls" in resp.json()
