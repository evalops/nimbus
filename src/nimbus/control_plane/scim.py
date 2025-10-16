"""SCIM v2.0 API utilities."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from fastapi import HTTPException, status


SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
SCIM_LIST_RESPONSE = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCIM_CREATE_REQUEST = "urn:ietf:params:scim:api:messages:2.0:CreateRequest"
SCIM_PATCH_OP = "urn:ietf:params:scim:api:messages:2.0:PatchOp"


@dataclass
class ScimResource:
    id: str
    external_id: str
    user_name: str
    display_name: Optional[str]
    active: bool


def scim_list_response(total: int, resources: list[dict]) -> dict:
    return {
        "schemas": [SCIM_LIST_RESPONSE],
        "totalResults": total,
        "Resources": resources,
        "itemsPerPage": len(resources),
        "startIndex": 1,
    }


def format_scim_user(record: dict) -> dict:
    return {
        "schemas": [SCIM_USER_SCHEMA],
        "id": str(record["id"]),
        "userName": record.get("email") or record.get("external_id"),
        "name": {
            "formatted": record.get("display_name") or record.get("email"),
        },
        "active": record.get("active", True),
        "externalId": record.get("external_id"),
        "emails": [
            {
                "value": record.get("email"),
                "primary": True,
            }
        ],
        "meta": {
            "created": _format_datetime(record.get("created_at")),
            "lastModified": _format_datetime(record.get("updated_at")),
        },
    }


def _format_datetime(value) -> Optional[str]:
    if not value:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def validate_scim_token(provided: str | None, expected: Optional[str]) -> None:
    if not expected:
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="SCIM disabled")
    if not provided:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing SCIM token")
    if provided != expected:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid SCIM token")


def parse_patch_operations(payload: dict) -> list[dict]:
    schemas = payload.get("schemas", [])
    if SCIM_PATCH_OP not in schemas:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid patch schema")
    operations = payload.get("Operations")
    if not isinstance(operations, list):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing patch operations")
    return operations
