FROM python:3.9-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy ALL application files
COPY . .

# Expose Streamlit's default port
EXPOSE 8501

# --- CONFIGURATION FIX ---
# We create a config.toml file to permanently fix the 400 Error.
# 1. enableXsrfProtection = false: TRUSTS the Azure Load Balancer (Fixes the 400 Error).
# 2. enableCORS = false: Allows the browser to talk to the container via Azure.
# 3. maxUploadSize = 2000: Allows 2GB uploads.
RUN mkdir -p /root/.streamlit
RUN echo "\
[server]\n\
headless = true\n\
address = '0.0.0.0'\n\
port = 8501\n\
maxUploadSize = 2000\n\
enableCORS = false\n\
enableXsrfProtection = false\n\
enableWebsocketCompression = false\n\
\n\
[browser]\n\
gatherUsageStats = false\n\
serverAddress = 'fslogix-analyser.purplegrass-6ec8783e.uksouth.azurecontainerapps.io'\n\
serverPort = 443\n\
" > /root/.streamlit/config.toml

# Run Streamlit (No flags needed now, they are in config.toml)
CMD ["streamlit", "run", "app.py"]