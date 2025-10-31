import sys
from types import ModuleType, SimpleNamespace


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


_ensure_module(
    "boto3",
    client=lambda *_args, **_kwargs: SimpleNamespace(),
    session=SimpleNamespace(Session=lambda: SimpleNamespace(client=lambda *_a, **_k: SimpleNamespace())),
)
_ensure_module(
    "botocore.exceptions",
    ClientError=type(
        "ClientError",
        (Exception,),
        {"__init__": lambda self, error_response=None, operation_name=None: Exception.__init__(self)},
    ),
)
_ensure_module(
    "pyroute2",
    IPRoute=SimpleNamespace,
    NetNS=SimpleNamespace,
    NetlinkError=Exception,
    netns=SimpleNamespace,
)
sigstore_module = ModuleType("sigstore")
sigstore_verify = _SigstoreVerify("sigstore.verify")
sigstore_module.verify = sigstore_verify
_ensure_module("sigstore", **{"verify": sigstore_verify})
_ensure_module(
    "sigstore.verify",
    VerificationMaterials=object,
    verifier=lambda *args, **kwargs: SimpleNamespace(verify=lambda *a, **kw: None),
)
# SAML optional dependency stubs
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

if "saml2" not in sys.modules:
    saml2_module = ModuleType("saml2")
    saml2_module.BINDING_HTTP_POST = "post"
    saml2_module.BINDING_HTTP_REDIRECT = "redirect"
    sys.modules["saml2"] = saml2_module

    saml2_client_module = ModuleType("saml2.client")
    saml2_client_module.Saml2Client = SimpleNamespace
    sys.modules["saml2.client"] = saml2_client_module

    saml2_config_module = ModuleType("saml2.config")
    saml2_config_module.Config = SimpleNamespace
    sys.modules["saml2.config"] = saml2_config_module

    saml2_metadata_module = ModuleType("saml2.metadata")
    saml2_metadata_module.entity_descriptor = lambda *args, **kwargs: SimpleNamespace(
        to_string=lambda: b"<EntityDescriptor/>"
    )
    sys.modules["saml2.metadata"] = saml2_metadata_module
