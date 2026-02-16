import os
from openai import AzureOpenAI


REQUIRED_ENV_VARS = [
    "AZURE_OPENAI_API_KEY",
    "AZURE_OPENAI_API_VERSION",
    "AZURE_OPENAI_ENDPOINT",
    "AZURE_OPENAI_DEPLOYMENT_NAME",
]


def get_missing_config():
    return [name for name in REQUIRED_ENV_VARS if not os.environ.get(name)]


def get_client_and_deployment():
    """Return (client, deployment_name, error_message)."""
    missing = get_missing_config()
    if missing:
        missing_list = ", ".join(missing)
        return None, None, f"Missing Azure OpenAI configuration: {missing_list}"

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
