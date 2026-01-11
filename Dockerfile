FROM python:3.9-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY app.py .

# Expose Streamlit's default port
EXPOSE 8501

# Run the app SECURELY
# Note: We set serverPort to 443 because Azure handles the SSL termination externally
CMD ["streamlit", "run", "app.py", \
    "--server.port=8501", \
    "--server.address=0.0.0.0", \
    "--browser.serverAddress=fslogix-analyser.purplegrass-6ec8783e.uksouth.azurecontainerapps.io", \
    "--browser.serverPort=443", \
    "--server.enableXsrfProtection=true", \
    "--server.enableCORS=true"]