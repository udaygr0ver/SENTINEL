# Welcome to SENTINEL

**SENTINEL** is an **Autonomous Multi-Agent Digital Forensics and Incident Response (DFIR) Platform** designed to automate security incident triage, multi-domain evidence correlation, and threat containment without exposing sensitive enterprise telemetry to public cloud AI APIs.

---

## 🎯 The Core Problem

Modern Security Operations Centers (SOCs) are overwhelmed by two systemic challenges:

1. **Alert Fatigue & Cognitive Overload:** Tier-1 and Tier-2 security analysts triage between 500 and 1,000 alerts daily. Over 80% are false positives or disconnected point-in-time alerts (e.g., an alert from the firewall, an alert from the endpoint, and an alert from the email gateway). Analysts must spend 30 to 60 minutes manually stitching disparate logs together to understand the root cause of an intrusion.
2. **Data Privacy & Legal Privilege Breaches:** Forensic telemetry (memory images, PCAP network captures, Windows event logs, and email bodies) frequently contains **unhashed passwords, customer PII, cryptographic keys, and proprietary corporate secrets**. Routing this data to commercial cloud AI models (such as OpenAI GPT-4, Google Gemini, or Microsoft Copilot) violates strict data privacy standards (**GDPR, HIPAA, SOC 2**) and compromises legal attorney-client privilege during corporate breach litigation.

---

## 💡 The SENTINEL Solution

SENTINEL eliminates this trade-off by deploying an **entirely local, air-gapped multi-agent investigation system**:

* **Zero Data Egress:** All models run locally via **Ollama (`llama3.1`)**, vector embeddings run on-premise with **ChromaDB**, and cases are tracked in an embedded **SQLite** database.
* **Deterministic + Probabilistic Guardrails:** Before any LLM reasoning takes place, raw evidence is evaluated against hardened **Sigma YAML rules** and compiled **YARA signatures** to eliminate false-negative dropouts for known threats.
* **Specialized Multi-Agent Collaboration:** Implemented as a **LangGraph Directed Acyclic Graph (DAG)**, specialized sub-agents independently evaluate their domain (Endpoint, Network, Memory, Phishing) before feeding into a **Lead SOC Correlation Analyst** that deduces attack causality.
* **Actionable Closed-Loop Response:** Automatically synthesizes custom **SOAR containment playbooks** (`netsh`, `iptables`, EDR API calls), multi-dialect **SIEM threat hunting queries** (Splunk SPL, Sentinel KQL, Elastic EQL), and structured **Jira / ServiceNow incident tickets**.

---

## 🌟 Key Capabilities

### 1. Multi-Source Forensic Ingestion
SENTINEL natively extracts, normalizes, and correlates evidence across all primary forensic domains:

| Artifact Type | File Formats | Forensic Extractions |
| :--- | :--- | :--- |
| **Endpoint Logs** | `.evtx` | Process execution (`4688`), User logon sessions (`4624`/`4625`), Service installations (`7045`), PowerShell ScriptBlock execution (`4104`) |
| **Network Streams** | `.pcap`, `.cap` | HTTP request/response payloads, Shannon entropy DNS tunneling detection, statistical C2 beacon volume clustering |
| **Memory Images** | `.mem`, `.raw`, `.vmem` | Volatility 3 integration for active processes (`pslist`), socket connections (`netscan`), and in-RAM code injections (`malfind`) |
| **Email Forensics** | `.eml` | SPF/DKIM header authentication auditing, sender spoofing detection, malicious URL extraction, attachment MD5 hashing |

### 2. Multi-Agent LangGraph Pipeline
A coordinated team of autonomous agents operating under a strictly validated schema:
- **💻 Endpoint Analyst Agent:** Evaluates EVTX logs, Sigma detections, and process trees.
- **🌐 Network Analyst Agent:** Inspects DNS tunneling anomalies, HTTP requests, and C2 beacons.
- **🧠 Memory Analyst Agent:** Analyzes process hollowing and RAM injections.
- **📧 Email / Phishing Analyst Agent:** Analyzes social engineering tactics and credential harvesting lures.
- **⚡ Lead SOC Correlation Agent:** Synthesizes domain findings into a unified, chronological attack narrative.
- **🛡️ SOAR Remediation Agent:** Generates immediate firewall blocking rules and EDR isolation commands.
- **🔍 SIEM Threat Hunter:** Auto-authors ready-to-deploy Splunk SPL, Azure KQL, and Elastic EQL hunting queries.
- **🎫 Automated Ticketing Engine:** Generates structured Jira and ServiceNow incident payloads.

### 3. Interactive SOC Dashboard
A 9-tab interactive command center powered by Streamlit:
- **📊 Interactive Timeline:** Plotly Gantt scatter chart displaying chronologically sequenced forensic events.
- **🔗 Attack Relationship Graph:** Force-directed Vis.js network graph connecting hosts, user accounts, and IOCs.
- **🎯 IOCs & MITRE TTPs:** Extracted indicators and dynamic ATT&CK technique badges.
- **🌍 Threat Intel Integration:** On-demand reputation lookups with VirusTotal and AbuseIPDB.
- **🔐 STIX 2.1 Export:** Downloadable OASIS CTI bundles for automated threat sharing.

---

## 🧭 Documentation Navigation

Explore the complete documentation:

* [**Architecture & Multi-Agent Flow**](architecture.md): Deep-dive into the LangGraph state machine, deterministic guardrails, and local vector RAG.
* [**User Guide & Walkthrough**](usage.md): Step-by-step instructions for local deployment, dashboard navigation, and automated CLI evaluation.
* [**Differentiation & Endterm Roadmap**](roadmap.md): Comprehensive comparison against SIEM, SOAR, and Cloud Copilots, plus the Sprint plan to the final capstone defense.
* [**Developer Guide**](development.md): How to add custom Sigma/YARA rules, write new parsers, and extend LangGraph sub-agents.
