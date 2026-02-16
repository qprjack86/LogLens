import os
from openai import AzureOpenAI, OpenAI


AZURE_REQUIRED_ENV_VARS = [
from openai import AzureOpenAI, OpenAI

AZURE_REQUIRED_ENV_VARS = [
    "AZURE_OPENAI_API_KEY",
    "AZURE_OPENAI_API_VERSION",
    "AZURE_OPENAI_ENDPOINT",
    "AZURE_OPENAI_DEPLOYMENT_NAME",
]

OPENAI_REQUIRED_ENV_VARS = [
    "OPENAI_API_KEY",
    "OPENAI_MODEL",
]


def _missing(required_names):
    return [name for name in required_names if not os.environ.get(name)]


def _env_any(*names):
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return None


def _missing_openai_config():
    missing = []
    if not os.environ.get("OPENAI_API_KEY"):
        missing.append("OPENAI_API_KEY")
    if not _env_any("OPENAI_MODEL", "LLM_MODEL"):
        missing.append("OPENAI_MODEL (or LLM_MODEL)")
    return missing


def get_missing_config(provider=None):
    provider = (provider or "").lower()
    if provider == "azure":
        return _missing(AZURE_REQUIRED_ENV_VARS)
    if provider in {"openai", "openai_compatible"}:
        return _missing_openai_config()
    return {
        "azure": _missing(AZURE_REQUIRED_ENV_VARS),
        "openai": _missing_openai_config(),
    }


def _select_provider():
    explicit = os.environ.get("LLM_PROVIDER", "").strip().lower()
    if explicit in {"azure", "openai", "openai_compatible"}:
        return explicit

    if not _missing(AZURE_REQUIRED_ENV_VARS):
        return "azure"
    if not _missing_openai_config():
        return "openai"
    return "unconfigured"


def get_client_and_deployment():
    """Return (client, model_or_deployment_name, error_message)."""
    provider = _select_provider()

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
        missing = _missing_openai_config()
        if missing:
            return None, None, f"Missing OpenAI-compatible configuration: {', '.join(missing)}"

        base_url = _env_any("OPENAI_BASE_URL", "OPENAI_API_BASE")
        try:
            kwargs = {"api_key": os.environ.get("OPENAI_API_KEY")}
            if base_url:
                kwargs["base_url"] = base_url
            client = OpenAI(**kwargs)
            model_name = _env_any("OPENAI_MODEL", "LLM_MODEL")
            return client, model_name, None
        except Exception as exc:
            return None, None, f"OpenAI-compatible client initialization error: {exc}"

    azure_missing = ", ".join(_missing(AZURE_REQUIRED_ENV_VARS))
    openai_missing = ", ".join(_missing_openai_config())
    return (
        None,
        None,
        "Missing model backend configuration. "
        f"Azure missing: [{azure_missing}] | OpenAI-compatible missing: [{openai_missing}]",
    )
def _missing(required_names):
    return [name for name in required_names if not os.environ.get(name)]

def _env_any(*names):
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return None

def _missing_openai_config():
    missing = []
    if not os.environ.get("OPENAI_API_KEY"):
        missing.append("OPENAI_API_KEY")
    if not _env_any("OPENAI_MODEL", "LLM_MODEL"):
        missing.append("OPENAI_MODEL (or LLM_MODEL)")
    return missing

def get_missing_config(provider=None):
    provider = (provider or "").lower()
    if provider == "azure":
        return _missing(AZURE_REQUIRED_ENV_VARS)
    if provider in {"openai", "openai_compatible"}:
        return _missing_openai_config()
    return {
        "azure": _missing(AZURE_REQUIRED_ENV_VARS),
        "openai": _missing_openai_config(),
    }

def _select_provider():
    explicit = os.environ.get("LLM_PROVIDER", "").strip().lower()
    if explicit in {"azure", "openai", "openai_compatible"}:
        return explicit

    if not _missing(AZURE_REQUIRED_ENV_VARS):
        return "azure"
    if not _missing_openai_config():
        return "openai"
    return "unconfigured"

def get_client_and_deployment():
    """Return (client, model_or_deployment_name, error_message)."""
    provider = _select_provider()

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
        missing = _missing_openai_config()
        if missing:
            return None, None, f"Missing OpenAI-compatible configuration: {', '.join(missing)}"

        base_url = _env_any("OPENAI_BASE_URL", "OPENAI_API_BASE")
        try:
            kwargs = {"api_key": os.environ.get("OPENAI_API_KEY")}
            if base_url:
                kwargs["base_url"] = base_url
            client = OpenAI(**kwargs)
            model_name = _env_any("OPENAI_MODEL", "LLM_MODEL")
            return client, model_name, None
        except Exception as exc:
            return None, None, f"OpenAI-compatible client initialization error: {exc}"

    azure_missing = ", ".join(_missing(AZURE_REQUIRED_ENV_VARS))
    openai_missing = ", ".join(_missing_openai_config())
    return (
        None,
        None,
        "Missing model backend configuration. "
        f"Azure missing: [{azure_missing}] | OpenAI-compatible missing: [{openai_missing}]",
    )