FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create data directories
RUN mkdir -p /app/data/cve_mirror /app/data/model_cache /app/data/reports /app/keys /app/logs

# Set environment variables
ENV PYTHONPATH=/app
ENV LLM_PROVIDER=ollama
ENV OLLAMA_BASE_URL=http://ollama:11434
ENV ZAP_API_URL=http://zap:8090
ENV DB_PATH=/app/data/grey_hat_agent.db

# Expose API port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/health')" || exit 1

# Run the API server
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
