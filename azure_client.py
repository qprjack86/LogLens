import os
import streamlit as st
from openai import AzureOpenAI

def get_secret(key):
    """
    Retrieves secret from Environment Variables (Cloud) or Streamlit Secrets (Local).
    """
    value = os.environ.get(key)
    if value: return value
    try: return st.secrets[key]
    except: return None

# Initialize the Client
try:
    client = AzureOpenAI(
        api_key=get_secret("AZURE_OPENAI_API_KEY"),
        api_version=get_secret("AZURE_OPENAI_API_VERSION"),
        azure_endpoint=get_secret("AZURE_OPENAI_ENDPOINT")
    )
    DEPLOYMENT_NAME = get_secret("AZURE_OPENAI_DEPLOYMENT_NAME")
except Exception as e:
    # We use st.error here so it shows up on the UI if connection fails
    st.error(f"Azure Connection Error: {e}")
    st.stop()