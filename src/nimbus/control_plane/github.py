"""Utilities for interacting with the GitHub API as a GitHub App."""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
import jwt

from ..common.schemas import RunnerRegistrationToken
from ..common.settings import ControlPlaneSettings

GITHUB_API_BASE = "https://api.github.com"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def build_app_jwt(settings: ControlPlaneSettings) -> str:
    """Return a short-lived JWT for GitHub App authentication."""

    now = int(time.time())
    payload = {
        "iat": now - 60,
        "exp": now + 540,
        "iss": settings.github_app_id,
    }
    return jwt.encode(payload, settings.github_app_private_key, algorithm="RS256")


@dataclass
class InstallationToken:
    token: str
    expires_at: datetime

    @property
    def is_valid(self) -> bool:
        if self.expires_at is None:
            return False
        return self.expires_at > _utc_now() + timedelta(seconds=30)


class GitHubAppClient:
    """Wraps GitHub API calls needed by the control plane."""

    def __init__(self, settings: ControlPlaneSettings, http_client: httpx.AsyncClient):
        self._settings = settings
        self._http = http_client
        self._cached_installation_token: Optional[InstallationToken] = None

    async def _exchange_installation_token(self) -> InstallationToken:
        jwt_token = build_app_jwt(self._settings)
        url = (
            f"{GITHUB_API_BASE}/app/installations/"
            f"{self._settings.github_app_installation_id}/access_tokens"
        )
        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "Accept": "application/vnd.github+json",
        }
        response = await self._http.post(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        expires_at = datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00"))
        token = InstallationToken(token=data["token"], expires_at=expires_at)
        self._cached_installation_token = token
        return token

    async def _get_installation_token(self) -> InstallationToken:
        if self._cached_installation_token and self._cached_installation_token.is_valid:
            return self._cached_installation_token
        return await self._exchange_installation_token()

    async def _installation_headers(self) -> dict[str, str]:
        token = await self._get_installation_token()
        return {
            "Authorization": f"token {token.token}",
            "Accept": "application/vnd.github+json",
        }

    async def create_runner_registration_token(
        self, repo_full_name: str
    ) -> RunnerRegistrationToken:
        url = f"{GITHUB_API_BASE}/repos/{repo_full_name}/actions/runners/registration-token"
        headers = await self._installation_headers()
        response = await self._http.post(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        expires_at = datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00"))
        return RunnerRegistrationToken(token=data["token"], expires_at=expires_at)
