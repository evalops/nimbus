from __future__ import annotations

import importlib.util
import sys
from types import ModuleType, SimpleNamespace

from pathlib import Path
from typing import Any, AsyncIterator, Dict

import httpx
import pytest


def _ensure_module(name: str, **attrs) -> None:
    if name in sys.modules:
        return
    module = ModuleType(name)
    for attr, value in attrs.items():
        setattr(module, attr, value)
    sys.modules[name] = module


class _SigstoreVerify(ModuleType):
    def __getattr__(self, name):
        raise ModuleNotFoundError(f"optional sigstore.verify dependency not installed: {name}")


def _install_optional_stubs() -> None:
    if importlib.util.find_spec("boto3") is None:
        _ensure_module(
            "boto3",
            client=lambda *_args, **_kwargs: SimpleNamespace(),
            session=SimpleNamespace(Session=lambda: SimpleNamespace(client=lambda *_a, **_k: SimpleNamespace())),
        )
    if importlib.util.find_spec("botocore.exceptions") is None:
        _ensure_module(
            "botocore.exceptions",
            ClientError=type(
                "ClientError",
                (Exception,),
                {"__init__": lambda self, error_response=None, operation_name=None: Exception.__init__(self)},
            ),
        )
    if importlib.util.find_spec("pyroute2") is None:
        _ensure_module(
            "pyroute2",
            IPRoute=SimpleNamespace,
            NetNS=SimpleNamespace,
            NetlinkError=Exception,
            netns=SimpleNamespace,
        )
    if importlib.util.find_spec("docker") is None:
        docker_module = ModuleType("docker")
        docker_module.DockerClient = SimpleNamespace
        docker_module.from_env = lambda *_args, **_kwargs: SimpleNamespace()
        errors_module = ModuleType("docker.errors")
        errors_module.DockerException = type("DockerException", (Exception,), {})
        errors_module.APIError = type("APIError", (Exception,), {})
        errors_module.NotFound = type("NotFound", (Exception,), {})
        errors_module.ImageNotFound = type("ImageNotFound", (Exception,), {})
        docker_module.errors = errors_module
        sys.modules.setdefault("docker", docker_module)
        sys.modules.setdefault("docker.errors", errors_module)
    if importlib.util.find_spec("sigstore.verify") is None:
        sigstore_verify = _SigstoreVerify("sigstore.verify")
        _ensure_module("sigstore", **{"verify": sigstore_verify})
        _ensure_module(
            "sigstore.verify",
            VerificationMaterials=object,
            verifier=lambda *args, **kwargs: SimpleNamespace(verify=lambda *a, **kw: None),
        )

    if importlib.util.find_spec("nimbus.control_plane.saml") is None and importlib.util.find_spec(
        "src.nimbus.control_plane.saml"
    ) is None:
        saml_module = ModuleType("nimbus.control_plane.saml")
        saml_module.SamlSettings = lambda **_kwargs: SimpleNamespace(**_kwargs)  # type: ignore[attr-defined]

        class _DummySamlAuthenticator:
            def __init__(self, *_args, **_kwargs):
                pass

            def generate_session_token(self, *_args, **_kwargs):
                return SimpleNamespace(to_dict=lambda: {"token": "stub"})

        saml_module.SamlAuthenticator = _DummySamlAuthenticator  # type: ignore[attr-defined]
        saml_module.SamlValidationError = Exception  # type: ignore[attr-defined]
        sys.modules.setdefault("nimbus.control_plane.saml", saml_module)
        sys.modules.setdefault("src.nimbus.control_plane.saml", saml_module)

    if importlib.util.find_spec("saml2") is None:
        saml2_module = ModuleType("saml2")
        saml2_module.BINDING_HTTP_POST = "post"
        saml2_module.BINDING_HTTP_REDIRECT = "redirect"
        sys.modules.setdefault("saml2", saml2_module)

        saml2_client_module = ModuleType("saml2.client")
        saml2_client_module.Saml2Client = SimpleNamespace
        sys.modules.setdefault("saml2.client", saml2_client_module)

        saml2_config_module = ModuleType("saml2.config")
        saml2_config_module.Config = SimpleNamespace
        sys.modules.setdefault("saml2.config", saml2_config_module)

        saml2_metadata_module = ModuleType("saml2.metadata")
        saml2_metadata_module.entity_descriptor = lambda *args, **kwargs: SimpleNamespace(
            to_string=lambda: b"<EntityDescriptor/>"
        )
        sys.modules.setdefault("saml2.metadata", saml2_metadata_module)


_install_optional_stubs()


from nimbus.docker_cache.app import create_app


@pytest.fixture
async def docker_cache_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[Dict[str, Any]]:
    secret = "cache-secret"
    storage = tmp_path / "storage"
    uploads = tmp_path / "uploads"
    db_path = tmp_path / "db.sqlite"
    audit_log = tmp_path / "audit.jsonl"

    monkeypatch.setenv("NIMBUS_CACHE_SHARED_SECRET", secret)
    monkeypatch.setenv("NIMBUS_DOCKER_CACHE_STORAGE_PATH", str(storage))
    monkeypatch.setenv("NIMBUS_DOCKER_CACHE_UPLOAD_PATH", str(uploads))
    monkeypatch.setenv("NIMBUS_DOCKER_CACHE_DB_PATH", str(db_path))
    monkeypatch.setenv("NIMBUS_DOCKER_CACHE_AUDIT_LOG", str(audit_log))

    app = create_app()
    lifespan = app.router.lifespan_context(app)
    await lifespan.__aenter__()
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver")

    try:
        yield {"client": client, "secret": secret, "audit_log": audit_log}
    finally:
        await client.aclose()
        await lifespan.__aexit__(None, None, None)
