# User Guide

SENTINEL can be run completely locally for maximum data privacy, or orchestrated via Docker Compose for production-grade REST API integrations.

## Running with Docker Compose (Recommended)

SENTINEL is containerized for seamless execution across operating systems.

```bash
# Clone the repository
git clone https://github.com/udaygr0ver/SENTINEL.git
cd SENTINEL

# Start the stack
docker-compose up -d --build
```

This will launch:
1. **SENTINEL API (FastAPI)** at `http://localhost:8000`
2. **SENTINEL Dashboard (Streamlit)** at `http://localhost:8501`

*(Make sure Ollama is running locally on port 11434 before starting the Docker stack!)*

## Navigating the Dashboard

1. **New Investigation:** Upload evidence files (`.evtx`, `.pcap`, etc.). Select the Local LLM. Add optional API keys for Threat Intel. Click **Start Analysis**.
2. **Case History:** Use the sidebar to toggle to historical cases. Click "View Report" to instantly load a past case from the SQLite database.
3. **Attack Graph:** View an interactive node-link mapping of compromised hosts and IOCs.

## REST API (FastAPI)

For automation or SIEM integration, interact directly with the FastAPI backend:

```bash
# Start a new analysis
curl -X POST "http://localhost:8000/api/v1/analyze" \
  -F "files=@evidence.pcap" \
  -F "llm_model=llama3.1"

# List past cases
curl "http://localhost:8000/api/v1/cases"
```
