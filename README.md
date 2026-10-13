# 🛡️ SENTINEL
**Autonomous Multi-Agent Digital Forensics & Incident Response (DFIR) Platform**

[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Architecture: LangGraph](https://img.shields.io/badge/Orchestration-LangGraph-purple.svg)](https://langchain-ai.github.io/langgraph/)
[![Engine: Ollama](https://img.shields.io/badge/LLM-Llama_3.1_(Local)-orange.svg)](https://ollama.ai/)
[![Privacy: 100% Local](https://img.shields.io/badge/Data_Privacy-100%25_Air--Gapped-green.svg)](#-privacy--zero-data-leakage)
[![Tests: Passing](https://img.shields.io/badge/Tests-10%2F10_Passing-brightgreen.svg)](#-testing--validation)

SENTINEL is an **air-gapped, privacy-preserving, autonomous multi-agent incident response system** built to resolve two critical challenges in modern Security Operations Centers (SOCs): **alert fatigue** and **data privacy/legal privilege**.

Instead of routing sensitive enterprise telemetry to public cloud AI APIs, SENTINEL operates **100% locally** using specialized **LangGraph** sub-agents, deterministic threat detection engines (Sigma & YARA), local vector embeddings (ChromaDB + MITRE ATT&CK), and local quantized LLMs (Llama 3.1 via Ollama). It correlates cross-domain forensic evidence into a unified chronological attack story, produces automated SOAR containment playbooks, generates multi-dialect SIEM detection queries, and exports standardized STIX 2.1 intelligence.

---

## 🚀 Key Features

* **Heterogeneous Evidence Ingestion:**
  * 💻 **Endpoint Logs (`.evtx`):** Windows Security (4624, 4625, 4688), PowerShell ScriptBlock (4104), and Service Installations (7045).
  * 🌐 **Network Captures (`.pcap`, `.cap`):** HTTP stream extraction, Shannon entropy DNS tunneling detection, and statistical C2 beacon clustering.
  * 🧠 **Memory Images (`.mem`, `.raw`, `.vmem`):** Volatility 3 integration for active processes, network sockets, and hidden code injections (`malfind`).
  * 📧 **Phishing & Email Artifacts (`.eml`):** SPF/DKIM header authentication auditing, malicious URL extraction, and credential harvest lure detection.
* **Hybrid Deterministic + Semantic Guardrails:**
  * **YARA & Sigma Engine:** Evaluates native rules against parsed events to eliminate false-negative dropouts for known threats before invoking LLMs.
  * **Local MITRE ATT&CK RAG:** Queries an on-premise ChromaDB vector store (`all-MiniLM-L6-v2`) to accurately tag artifacts with verified Enterprise Technique IDs.
* **7-Agent Autonomous Pipeline:**
  * **Domain Specialists:** Dedicated sub-agents for Endpoint, Network, Memory, and Email forensics keep prompt context small, focused, and hallucination-free.
  * **Lead SOC Correlation Analyst:** Synthesizes multi-source intelligence into a cohesive, chronological incident causality narrative.
  * **SOAR Remediation Agent:** Generates tailored network containment rules (`netsh`, `iptables`), EDR isolation commands (CrowdStrike, Defender), and new detection signatures.
  * **SIEM Threat Hunter:** Auto-authors hunting queries in **Splunk SPL**, **Microsoft Sentinel KQL**, and **Elastic EQL**.
  * **Automated Ticketing Engine:** Produces structured Jira / ServiceNow REST API JSON incident payloads.
* **Presentation-Grade SOC Dashboard:**
  * 📊 **Plotly Gantt Timeline:** Interactive chronological scatter timeline with severity color-coding.
  * 🔗 **Attack Relationship Graph:** Interactive Force-Directed Network Graph (Vis.js / `streamlit-agraph`) linking compromised hosts, users, IOCs, and events.
  * 📂 **Persistent SQLite Case Archive:** Preserves past case findings, reports, and extracted artifacts with zero re-computation.
  * 🔐 **STIX 2.1 Export:** Generates OASIS-compliant CTI bundles for automated threat intelligence sharing.

---

## 🔒 Privacy & Zero Data Leakage

In real-world incident response, disk dumps, packet captures, and email records contain **unhashed credentials, proprietary intellectual property, employee PII, and cryptographic keys**. 

Sending raw telemetry to external commercial cloud AI models:
1. Violates enterprise compliance mandates (**GDPR, HIPAA, PCI-DSS, SOC 2**).
2. Forfeits attorney-client legal privilege during breach litigation.

**SENTINEL runs entirely on your local hardware:**
* Zero external network egress required.
* Local quantized weights via **Ollama (`llama3.1:latest`)**.
* Local vector database via **ChromaDB**.
* Local relational storage via **SQLite (`data/sentinel.db`)**.

---

## 🛠️ Tech Stack

| Layer | Component | Description |
| :--- | :--- | :--- |
| **Agent Orchestration** | [LangGraph](https://langchain-ai.github.io/langgraph/) | Directed Acyclic Graph (DAG) state machine for multi-agent workflows |
| **Local LLM Engine** | [Ollama](https://ollama.ai/) | Local inference for Llama 3.1 (8B / 70B) or Mistral |
| **Knowledge Retrieval (RAG)** | [ChromaDB](https://www.trychroma.com/) | Local vector database indexing MITRE ATT&CK Enterprise STIX 2.1 |
| **Embeddings** | `sentence-transformers` | `all-MiniLM-L6-v2` dense vector representations |
| **Forensic Parsers** | `python-evtx`, `scapy`, `volatility3` | Native parsers for Windows Event Logs, PCAPs, and RAM dumps |
| **Deterministic Engines** | `yara-python`, `PyYAML` | In-memory signature evaluation and custom Sigma detection rules |
| **Frontend & Visualizations** | Streamlit, Plotly, `streamlit-agraph` | Interactive SOC web dashboard, Gantt charts, and force-directed graphs |
| **Case Persistence** | SQLite 3 | Normalized forensic case management and instant replay |
| **Standards & Interoperability** | STIX 2.1, JSON, Markdown | Machine-readable CTI export and human-readable executive summaries |

---

## ⚙️ Multi-Agent Architecture

The pipeline processes forensic telemetry through a structured, multi-stage DAG:

```
[ Upload Files (.evtx, .pcap, .mem, .eml) ]
                     │
                     ▼
             1. PARSER NODE
      ┌──────────────┴──────────────┐
      │  • Extract raw events       │
      │  • Scan YARA signatures     │
      │  • Match Sigma YAML rules   │
      │  • Query MITRE ATT&CK RAG   │
      └──────────────┬──────────────┘
                     │ (Normalized Artifacts)
   ┌─────────────────┼─────────────────┬─────────────────┐
   ▼                 ▼                 ▼                 ▼
Endpoint          Network           Memory             Email
 Analyst           Analyst           Analyst          Analyst
(EVTX/Sigma)    (PCAP/Entropy)    (Volatility)     (SPF/DKIM/Lures)
   └─────────────────┼─────────────────┴─────────────────┘
                     │ (Domain Intelligence Summaries)
                     ▼
        2. LEAD SOC CORRELATION AGENT
   (Synthesizes Cross-Domain Causality & Timeline)
                     │
                     ▼
             3. REPORTER NODE
   (Markdown Forensic Report & STIX 2.1 Bundle)
                     │
                     ▼
         4. SOAR REMEDIATION AGENT
   (Firewall Netsh/Iptables & EDR Isolation APIs)
                     │
                     ▼
          5. SIEM THREAT HUNTER
   (Splunk SPL, Sentinel KQL, Elastic EQL Queries)
                     │
                     ▼
       6. AUTOMATED TICKETING ENGINE
   (Jira / ServiceNow Incident API JSON Payload)
                     │
                     ▼
          7. SOC DASHBOARD REPLAY
   (Plotly Timeline + Interactive Vis.js Attack Graph)
```

---

## 💻 Local Setup & Installation

### Prerequisites
* **Python 3.9+**
* **Ollama** installed and running on your system ([Download Ollama](https://ollama.ai/))
* Minimum 16GB RAM recommended for local 8B model inference

### 1. Clone the Repository
```bash
git clone https://github.com/udaygr0ver/SENTINEL.git
cd SENTINEL
```

### 2. Create and Activate a Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Pull the Local LLM Model
Ensure the Ollama service is active, then pull the target model:
```bash
ollama pull llama3.1
```

### 5. (Optional) Ingest MITRE ATT&CK Knowledge Base
The local ChromaDB vector store is pre-initialized in `data/chroma_db`. If you wish to re-ingest the latest MITRE ATT&CK Enterprise STIX dataset:
```bash
python -m src.kb.ingest_mitre
```

---

## 🚀 Running the Platform

### Option A: Interactive SOC Dashboard (Recommended)
Launch the Streamlit web dashboard:
```bash
streamlit run src/app.py
```
Open your browser at **`http://localhost:8501`**.

1. Drag-and-drop evidence files from `demo_data/`:
   * `demo_data/phishing_attack.eml` (Phishing email lure)
   * `demo_data/lateral_movement.pcap` (DNS tunneling & C2 traffic)
   * `demo_data/security_log.evtx` (Process creation & logon events)
2. Click **🚀 Run Analysis**.
3. Inspect real-time agent progression across the 9 interactive tabs:
   * **📊 Timeline:** Plotly chronological sequence & AI narrative.
   * **🔗 Attack Graph:** Interactive force-directed node-link mapping.
   * **🤖 Agent Summaries:** Detailed breakdown from each forensic specialist.
   * **🎯 IOCs & Evidence:** Extracted IPs, domains, and MITRE TTP badges.
   * **🌍 Threat Intel:** VirusTotal & AbuseIPDB enrichment results.
   * **🛡️ SOAR Remediation:** Auto-generated firewall and containment commands.
   * **🔍 Threat Hunting:** Ready-to-deploy Splunk SPL, KQL, and EQL queries.
   * **🎫 SOC Ticket:** Jira/ServiceNow API JSON payload.
   * **📋 Report & STIX:** Full Markdown report & downloadable STIX 2.1 JSON bundle.

### Option B: Headless Automated CLI Demo
To run the complete 7-agent pipeline headlessly and generate a comprehensive markdown report:
```bash
python run_demo.py
```
Outputs are automatically written to `demo_output.md`.

### Option C: REST API (FastAPI)
For headless ingestion from SIEM forwarders or automated pipelines:
```bash
uvicorn src.api:app --reload --port 8000
```
Interactive OpenAPI documentation will be accessible at **`http://localhost:8000/docs`**.

---

## 🧪 Testing & Validation

SENTINEL maintains a strict automated test suite covering all forensic parsers and scanners:

```bash
pytest -v
```

```
============================== test session starts ==============================
collected 10 items

tests/test_eml_parser.py .                                               [ 10%]
tests/test_evtx_parser.py .                                              [ 20%]
tests/test_mem_parser.py .                                               [ 30%]
tests/test_pcap_parser.py ....                                           [ 70%]
tests/test_sigma_scanner.py ..                                           [ 90%]
tests/test_yara_scanner.py .                                             [100%]

============================== 10 passed in 0.35s ==============================
```

---

## 📁 Repository Structure

```
SENTINEL/
├── data/
│   ├── chroma_db/            # Local vector store with MITRE ATT&CK embeddings
│   ├── pcap/                 # Sample PCAP test fixtures
│   ├── evtx/                 # Sample Windows Event Log fixtures
│   └── sentinel.db           # Persistent SQLite case history database
├── demo_data/                # Verified test fixtures for evaluation & demos
│   ├── lateral_movement.pcap # Scapy capture (DNS tunnel + HTTP C2 beacons)
│   ├── phishing_attack.eml   # Spoofed Office365 phishing lure
│   └── security_log.evtx     # Real Windows process creation events
├── docs/                     # Full MkDocs documentation site
│   ├── index.md              # Documentation overview
│   ├── architecture.md       # Multi-agent architecture and DAG flow
│   ├── usage.md              # User guide, dashboard walkthrough & CLI
│   ├── roadmap.md            # Differentiation matrix & endterm plan
│   └── development.md        # Developer guide: writing parsers & rules
├── rules/
│   ├── sigma/                # Custom Sigma YAML detection rules
│   └── yara/                 # YARA malware and attack pattern rules
├── src/
│   ├── agent/
│   │   ├── graph.py          # LangGraph DAG state machine compiler
│   │   ├── nodes.py          # Sub-agent implementations (7 specialized nodes)
│   │   ├── state.py          # TypedDict AgentState schema
│   │   └── tools.py          # Agent forensic utility tools
│   ├── db/
│   │   └── case_manager.py   # SQLite persistence layer
│   ├── enrichment/
│   │   └── threat_intel.py   # VirusTotal & AbuseIPDB reputation clients
│   ├── kb/
│   │   ├── ingest_mitre.py   # STIX 2.1 MITRE ATT&CK vector ingestion
│   │   └── retriever.py      # Semantic similarity search client
│   ├── parsers/              # Forensic parser suite
│   │   ├── eml_parser.py     # Email & phishing header analyzer
│   │   ├── evtx_parser.py    # Windows EVTX XML parser
│   │   ├── mem_parser.py     # Volatility 3 RAM parser
│   │   ├── pcap_parser.py    # Scapy PCAP & DNS entropy parser
│   │   ├── sigma_scanner.py  # In-memory Sigma rule evaluator
│   │   └── yara_scanner.py   # Compiled YARA signature scanner
│   ├── reporting/
│   │   ├── graph_viz.py      # Vis.js attack relationship graph
│   │   ├── stix_exporter.py  # OASIS STIX 2.1 bundle exporter
│   │   └── timeline_viz.py   # Plotly chronological Gantt timeline
│   ├── api.py                # FastAPI REST interface
│   ├── app.py                # Main Streamlit SOC dashboard
│   └── schema.py             # Normalized ForensicArtifact Pydantic model
├── tests/                    # Pytest test suite (100% passing)
├── mkdocs.yml                # MkDocs Material configuration
├── requirements.txt          # Production dependencies
└── run_demo.py               # Standalone end-to-end evaluation runner
```

---

## 🗺️ Roadmap to Endterm

* **Sprint 1 (Weeks 1–2):** Quantitative benchmarking against public cyber ranges (**Splunk BOTS**, **DARPA Transparent Computing**), measuring TTP precision/recall and Mean Time to Correlate (MTTC).
* **Sprint 2 (Weeks 3–4):** Autonomous agent tool-use (interactive Base64 deobfuscation, sliding-window entropy scanners) and Model Context Protocol (MCP) server support.
* **Sprint 3 (Weeks 5–6):** Enterprise multi-cloud telemetry ingestion (Linux `auditd`, AWS CloudTrail, and Azure Activity Logs).
* **Sprint 4 (Weeks 7–8):** Closed-loop adversary emulation using **Atomic Red Team** to verify auto-generated Sigma/firewall rules against active attack simulations.
* **Sprint 5 (Weeks 9–10):** Single-command Docker containerization and formal IEEE/ACM capstone thesis submission.

---

## 👥 Author & Acknowledgments

* **Lead Developer:** [Uday Grover](https://github.com/udaygr0ver)
* **Frameworks & Research Grounding:** MITRE ATT&CK®, OASIS CTI STIX 2.1, LangChain / LangGraph, Ollama, SigmaHQ, and YARA.
