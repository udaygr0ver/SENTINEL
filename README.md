# 🛡️ SENTINEL
**Autonomous AI Digital Forensics & Incident Response (DFIR) Agent**

SENTINEL is a privacy-first, autonomous forensic agent built to combat alert fatigue in Security Operations Centers (SOCs). It ingests disparate forensic artifacts (disk, network, and memory), semantically maps them to the MITRE ATT&CK framework via a local RAG pipeline, and uses local LLMs to generate chronological attack narratives and standardized STIX 2.1 threat intelligence.

All data is processed strictly locally, ensuring **zero data leakage**.

![Dashboard Status](https://img.shields.io/badge/Status-Active-success)
![Data Privacy](https://img.shields.io/badge/Privacy-100%25_Local-blue)

---

## 🚀 Key Features

* **Multi-Source Artifact Ingestion:** Parses endpoint logs (`.evtx`), network captures (`.pcap`, `.cap`), and memory dumps (`.mem`, `.raw`) natively.
* **RAG-Powered Threat Intel:** Uses ChromaDB to semantically map extracted artifacts to MITRE ATT&CK techniques in real-time.
* **Deterministic AI Workflow:** Built on **LangGraph** (Parser → Enrich → Correlate → Report), ensuring the agent follows a strict, auditable pipeline to prevent LLM hallucinations.
* **Local LLM Correlation:** Leverages Ollama (Llama 3.1) for natural language timeline generation and correlation without exposing sensitive logs to external APIs.
* **Automated CTI Generation:** Autonomously outputs standardized STIX 2.1 JSON bundles for seamless SOC/SOAR integration.
* **Professional SOC Dashboard:** Interactive Streamlit UI for visual timeline reconstruction, IOC tagging, and report downloads.

---

## 🛠️ Tech Stack

* **AI & Agent Workflow:** LangChain, LangGraph, Ollama (Llama 3.1)
* **Vector Store & RAG:** ChromaDB, HuggingFace `sentence-transformers`
* **Forensic Parsers:** `python-evtx`, `scapy`, `volatility3`
* **Frontend:** Streamlit
* **Reporting:** STIX 2.1, Markdown

---

## ⚙️ Architecture Pipeline

1. **Upload:** User drops `.evtx`, `.pcap`, or `.mem` files into the Streamlit dashboard.
2. **Parse:** Artifacts are normalized into `ForensicArtifact` Pydantic models.
3. **Enrich:** High-value artifacts (e.g., suspicious PowerShell, HTTP traffic) are embedded and matched against MITRE ATT&CK data via HNSW cosine similarity.
4. **Correlate:** Enriched artifacts are fed into Llama 3.1, guided by a strict SOC Defender system prompt, to deduce causality and generate an attack narrative.
5. **Report:** The system generates a visual timeline, extracts IOCs (IPs, hashes), and exports a valid STIX 2.1 bundle for downstream blocking/hunting.

---

## 💻 Local Setup

Since this project relies on local LLM inference, a capable machine (Apple Silicon or dedicated GPU) is recommended.

1. **Clone the repository:**
   ```bash
   git clone https://github.com/udaygr0ver/SENTINEL.git
   cd SENTINEL
   ```
2. **Install Python dependencies:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
3. **Install Ollama & Pull Models:**
   Install [Ollama](https://ollama.ai/) and download the required LLM:
   ```bash
   ollama run llama3.1
   ```
4. **Launch the Dashboard:**
   ```bash
   streamlit run src/app.py
   ```
