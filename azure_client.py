import os
from openai import AzureOpenAI


def get_secret(key: str):
    """Retrieve a required secret from environment variables."""
    return os.environ.get(key)


def _validate_config(config: dict):
    missing = [k for k, v in config.items() if not v]
    if missing:
        missing_list = ", ".join(missing)
        raise RuntimeError(f"Missing Azure OpenAI configuration: {missing_list}")


config = {
    "AZURE_OPENAI_API_KEY": get_secret("AZURE_OPENAI_API_KEY"),
    "AZURE_OPENAI_API_VERSION": get_secret("AZURE_OPENAI_API_VERSION"),
    "AZURE_OPENAI_ENDPOINT": get_secret("AZURE_OPENAI_ENDPOINT"),
    "AZURE_OPENAI_DEPLOYMENT_NAME": get_secret("AZURE_OPENAI_DEPLOYMENT_NAME"),
}

_validate_config(config)

client = AzureOpenAI(
    api_key=config["AZURE_OPENAI_API_KEY"],
    api_version=config["AZURE_OPENAI_API_VERSION"],
    azure_endpoint=config["AZURE_OPENAI_ENDPOINT"],
)
DEPLOYMENT_NAME = config["AZURE_OPENAI_DEPLOYMENT_NAME"]
