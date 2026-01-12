FROM python:3.9-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy ALL application files
COPY . .

# Expose Streamlit's default port
EXPOSE 8501

# Set a fixed Secret for XSRF protection (Fixes 400 Error on Uploads)
# In production, you would pass this as an environment variable, but setting it here 
# ensures your uploads don't fail if the container restarts.
ENV STREAMLIT_SERVER_COOKIE_SECRET="89327598237589237589237589"

# Run the app SECURELY
# 1. We KEEP XsrfProtection and CORS enabled (True).
# 2. We set 'browser.serverAddress' so Streamlit trusts the Azure URL.
# 3. We removed 'browser.serverPort' to prevent mismatches (browsers often hide port 443).
CMD ["streamlit", "run", "app.py", \
    "--server.port=8501", \
    "--server.address=0.0.0.0", \
    "--browser.serverAddress=fslogix-analyser.purplegrass-6ec8783e.uksouth.azurecontainerapps.io", \
    "--server.enableXsrfProtection=true", \
    "--server.enableCORS=true", \
    "--server.enableWebsocketCompression=false", \
    "--server.fileWatcherType=none"]