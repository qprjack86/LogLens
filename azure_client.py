import os
from openai import AzureOpenAI, OpenAI

AZURE_REQUIRED_ENV_VARS = [
    "AZURE_OPENAI_API_KEY",
    "AZURE_OPENAI_API_VERSION",
    "AZURE_OPENAI_ENDPOINT",
    "AZURE_OPENAI_DEPLOYMENT_NAME",
]

def _missing(required_names):
    return [name for name in required_names if not os.environ.get(name)]


def _profile_env_name(profile, base_name):
    return f"DEEP_{base_name}" if profile == "deep" else base_name

def _env_any(*names):
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return None

def _missing_openai_config(profile="default"):
    missing = []
    if not os.environ.get(_profile_env_name(profile, "OPENAI_API_KEY")):
        missing.append("OPENAI_API_KEY")
    if not _env_any(
        _profile_env_name(profile, "OPENAI_MODEL"),
        _profile_env_name(profile, "LLM_MODEL"),
    ):
        missing.append("OPENAI_MODEL (or LLM_MODEL)")
    return missing


def _select_provider(profile="default"):
    explicit = os.environ.get(_profile_env_name(profile, "LLM_PROVIDER"), "").strip().lower()
    if explicit in {"azure", "openai", "openai_compatible"}:
        return explicit

    if profile == "default" and not _missing(AZURE_REQUIRED_ENV_VARS):
        return "azure"
    if not _missing_openai_config(profile=profile):
        return "openai"
    return "unconfigured"

def get_missing_config(provider=None, profile="default"):
    # 1. Auto-detect provider if not explicitly passed
    if not provider:
        provider = _select_provider(profile=profile)

    provider = (provider or "").lower()
    
    # 2. Prepare the result dictionary (Default to empty lists = No errors)
    res = {
        "azure": [],
        "openai": []
    }
    
    # 3. Only check the relevant config for the ACTIVE provider
    if provider == "azure":
        res["azure"] = _missing(AZURE_REQUIRED_ENV_VARS) if profile == "default" else []
    elif provider in {"openai", "openai_compatible"}:
        res["openai"] = _missing_openai_config(profile=profile)
    else:
        # If unconfigured, show everything that is missing so user can decide
        res["azure"] = _missing(AZURE_REQUIRED_ENV_VARS) if profile == "default" else []
        res["openai"] = _missing_openai_config(profile=profile)
        
    return res

def get_client_and_deployment(profile="default"):
    """Return (client, model_or_deployment_name, error_message)."""
    provider = _select_provider(profile=profile)

    if provider == "azure":
        missing = _missing(AZURE_REQUIRED_ENV_VARS)
        if missing:
            return None, None, f"Missing Azure OpenAI configuration: {', '.join(missing)}"

        try:
            client = AzureOpenAI(
                api_key=os.environ.get("AZURE_OPENAI_API_KEY"),
                api_version=os.environ.get("AZURE_OPENAI_API_VERSION"),
                azure_endpoint=os.environ.get("AZURE_OPENAI_ENDPOINT"),
            )
            deployment_name = os.environ.get("AZURE_OPENAI_DEPLOYMENT_NAME")
            return client, deployment_name, None
        except Exception as exc:
            return None, None, f"Azure client initialization error: {exc}"

    if provider in {"openai", "openai_compatible"}:
        missing = _missing_openai_config(profile=profile)
        if missing:
            return None, None, f"Missing OpenAI-compatible configuration: {', '.join(missing)}"

        base_url = _env_any(
            _profile_env_name(profile, "OPENAI_BASE_URL"),
            _profile_env_name(profile, "OPENAI_API_BASE"),
        )
        try:
            kwargs = {"api_key": os.environ.get(_profile_env_name(profile, "OPENAI_API_KEY"))}
            if base_url:
                kwargs["base_url"] = base_url
            client = OpenAI(**kwargs)
            model_name = _env_any(
                _profile_env_name(profile, "OPENAI_MODEL"),
                _profile_env_name(profile, "LLM_MODEL"),
            )
            return client, model_name, None
        except Exception as exc:
            return None, None, f"OpenAI-compatible client initialization error: {exc}"

    azure_missing = ", ".join(_missing(AZURE_REQUIRED_ENV_VARS))
    openai_missing = ", ".join(_missing_openai_config(profile=profile))
    return (
        None,
        None,
        "Missing model backend configuration. "
        f"Azure missing: [{azure_missing}] | OpenAI-compatible missing: [{openai_missing}]",
    )


def get_provider(profile="default"):
    return _select_provider(profile=profile)


def get_api_style(profile="default"):
    """Return preferred API style: auto, chat, or responses."""
    style = os.environ.get(_profile_env_name(profile, "OPENAI_API_STYLE"), "auto").strip().lower()
    return style if style in {"auto", "chat", "responses"} else "auto"
