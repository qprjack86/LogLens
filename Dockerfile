FROM python:3.9.18-slim

# Security: Prevent Python from writing pyc files
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Security: Create a non-root user
RUN groupadd -r appgroup && \
useradd -r -d /home/appuser -m appuser

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Security: Copy files with correct ownership
COPY --chown=appuser:appgroup . .

# Security: Create .streamlit folder with user permissions
RUN mkdir -p /app/.streamlit && \
    chown -R appuser:appgroup /app /home/appuser

# Security: Switch to non-root user
USER appuser

# Expose Port
EXPOSE 8501


# --- LOCAL CONFIGURATION ---
# 1. enableXsrfProtection=false: Required because localhost doesn't send secure headers.
# 2. enableCORS=false: Allows local browser access.
# 3. No serverAddress: defaults to localhost.
RUN echo "\
[server]\n\
headless = true\n\
address = '0.0.0.0'\n\
port = 8501\n\
maxUploadSize = 2000\n\
enableCORS = false\n\
enableXsrfProtection = false\n\
enableWebsocketCompression = false\n\
" > /app/.streamlit/config.toml

CMD ["streamlit", "run", "app.py"]