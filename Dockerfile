FROM python:3.9-slim

WORKDIR /app

# Install system dependencies (needed for yara-python, scapy, etc)
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    libpcap-dev \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Also install FastAPI deps
RUN pip install --no-cache-dir fastapi uvicorn python-multipart

COPY . .

# Expose ports for both API and UI
EXPOSE 8000
EXPOSE 8501

# The command is overridden in docker-compose.yml
CMD ["uvicorn", "src.api:app", "--host", "0.0.0.0", "--port", "8000"]
