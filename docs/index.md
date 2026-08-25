# Welcome to SENTINEL

**SENTINEL** is an Autonomous Forensic Agent designed to triage digital evidence (EVTX, PCAP, Memory Dumps) automatically using Multi-Agent Large Language Models (LLMs) and deterministic Threat Intelligence engines (YARA/Sigma).

## Features

- **Multi-Agent Orchestration**: Specialized Endpoint, Network, and Memory analyst agents powered by LangGraph.
- **Deep Artifact Parsing**: 
    - **Endpoint**: Parses EVTX logs and matches against Sigma rules.
    - **Network**: Extracts HTTP traffic, detects DNS Tunneling (via Shannon Entropy), and flags C2 Beacons (via statistical analysis).
    - **Memory**: Analyzes Volatility3 RAM dumps.
- **Threat Intelligence Integrations**: Real-time enrichment against VirusTotal and AbuseIPDB.
- **Interactive UI**: View a force-directed attack graph and chronological incident narrative in a beautiful Streamlit dashboard.
- **STIX 2.1 Export**: Download industry-standard Threat Intelligence bundles.
- **100% Local Processing**: Runs entirely locally via Ollama, keeping sensitive evidence private.

## Getting Started

Check out the [User Guide](usage.md) to learn how to deploy SENTINEL using Docker Compose.
