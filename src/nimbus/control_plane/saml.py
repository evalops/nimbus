"""SAML SSO integration helpers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import structlog
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config
from saml2.metadata import entity_descriptor


LOGGER = structlog.get_logger("nimbus.control_plane.saml")


@dataclass
class SamlSettings:
    entity_id: str
    acs_url: str
    metadata_path: Path
    sp_certificate: Optional[Path] = None
    sp_private_key: Optional[Path] = None


class SamlAuthenticator:
    """Wrapper around pysaml2 client with simplified API."""

    def __init__(self, settings: SamlSettings) -> None:
        self._settings = settings
        config = self._build_config(settings)
        self._client = Saml2Client(config=config)

    @staticmethod
    def _build_config(settings: SamlSettings) -> Saml2Config:
        metadata_file = str(settings.metadata_path)
        sp_config = {
            "entityid": settings.entity_id,
            "allow_unknown_attributes": True,
            "service": {
                "sp": {
                    "name": "Nimbus Control Plane",
                    "endpoints": {
                        "assertion_consumer_service": [
                            (settings.acs_url, BINDING_HTTP_POST),
                        ],
                    },
                    "authn_requests_signed": bool(settings.sp_private_key),
                    "want_response_signed": True,
                    "want_assertions_signed": True,
                }
            },
            "metadata": {"local": [metadata_file]},
            "xmlsec_binary": None,
        }

        if settings.sp_certificate and settings.sp_private_key:
            sp_config["key_file"] = str(settings.sp_private_key)
            sp_config["cert_file"] = str(settings.sp_certificate)

        saml_config = Saml2Config()
        saml_config.load(sp_config)
        saml_config.allow_unknown_attributes = True
        return saml_config

    def prepare_redirect(self, relay_state: Optional[str] = None) -> tuple[str, dict[str, str]]:
        request_id, info = self._client.prepare_for_authenticate(relay_state=relay_state)
        for _key, value in info["headers"]:
            # info includes a location header with redirect URL
            if _key.lower() == "location":
                return value, {"SAMLRequest": info["data"], "RelayState": relay_state or ""}
        raise RuntimeError("SAML redirect location not found")

    def parse_assertion(self, saml_response: str) -> dict[str, object]:
        authn_response = self._client.parse_authn_request_response(saml_response, BINDING_HTTP_POST)
        authn_response.get_identity()
        attributes = authn_response.ava
        name_id = authn_response.get_subject().text
        session_info = authn_response.session_info()
        LOGGER.info("SAML assertion parsed", name_id=name_id)
        return {
            "name_id": name_id,
            "attributes": attributes,
            "session_info": session_info,
        }

    def metadata_xml(self) -> str:
        ed = entity_descriptor(str(self._client.config.entityid), conf=self._client.config)
        return ed.to_string().decode("utf-8")
