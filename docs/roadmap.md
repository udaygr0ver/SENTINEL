# Competitive Differentiation & Endterm Roadmap

This document outlines SENTINEL's unique scientific and engineering advantages over pre-existing cybersecurity platforms, followed by the week-by-week development roadmap leading to the final Endterm capstone defense.

---

## 🥊 How SENTINEL Differs from Pre-Existing Solutions

To understand SENTINEL's novelty, we benchmark it against the four prevailing paradigms in enterprise cybersecurity:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                               CYBERSECURITY ARCHITECTURES                              │
├────────────────────────┬────────────────────────┬──────────────────────────────────────┤
│ 1. Legacy SIEM / SOAR  │ 2. Cloud AI Copilots   │ 3. Raw DFIR Tools    │ 4. SENTINEL   │
│ (Splunk, Microsoft     │ (Microsoft Security    │ (Autopsy, FTK,       │ (Autonomous,  │
│ Sentinel, Cortex SOAR) │ Copilot, Charlotte AI) │ Volatility CLI)      │ Local Multi-  │
│                        │                        │                      │ Agent DFIR)   │
└────────────────────────┴────────────────────────┴──────────────────────┴───────────────┘
```

### 1. vs. Traditional SIEM & SOAR (Splunk, Microsoft Sentinel, Cortex XSOAR)
* **The Problem:** Traditional SIEMs are passive, rule-based log aggregation databases. During a multi-stage attack, they generate dozens of disconnected alerts (e.g., an alert from the firewall, an alert from Windows event logs, an alert from the email gateway). Human Tier-1/Tier-2 analysts must spend 45+ minutes manually stitching logs together into an incident story. SOAR playbooks are rigid Python scripts that break as soon as an attacker modifies minor command-line parameters.
* **The SENTINEL Advantage:** SENTINEL is **autonomous and generative**. Instead of creating 10 disconnected alerts, it synthesizes the entire intrusion into a **single, chronological causality narrative** (e.g., *"Attacker lured user via phishing email → established C2 beacon → executed PowerShell → exfiltrated credentials"*), and dynamically authors custom containment rules (firewall, EDR API, Sigma).

### 2. vs. Cloud-Based AI Tools (Microsoft Security Copilot, CrowdStrike Charlotte AI)
* **The Problem:** Cloud Copilots send confidential enterprise telemetry over the WAN to commercial cloud LLMs. Incident response artifacts contain proprietary secrets, unhashed passwords, user PII, and sensitive network architecture. **Sending this data to external APIs violates GDPR, HIPAA, SOC 2, and destroys legal attorney-client privilege during corporate breach litigation.** Furthermore, they lock customers into proprietary ecosystems (Defender/Falcon).
* **The SENTINEL Advantage:** **100% Privacy-Preserving and Air-Gapped.** Zero bytes leave the machine. It runs entirely on local quantized open-weights models (`Llama 3.1` via Ollama) and local vector embeddings (`ChromaDB`). It is vendor-agnostic and ingests raw open forensic standards (`.evtx`, `.pcap`, `.mem`, `.eml`).

### 3. vs. Forensic Suites (Autopsy, FTK Imager, Volatility)
* **The Problem:** These tools are **extractors, not analyzers**. They dump massive tables of raw data (e.g., 500 processes from `pslist`, thousands of raw packets in Wireshark) but cannot deduce *intent*, correlate across domains, or recommend defensive actions.
* **The SENTINEL Advantage:** SENTINEL acts as a **virtual Tier-2/Tier-3 forensic analyst team**. It reasons over raw evidence, calculates entropy to identify DNS tunnels, extracts IOCs, matches MITRE ATT&CK techniques, and auto-generates SIEM queries and Jira tickets.

### 4. vs. Generic LLM Chatbots (ChatGPT / Prompt Wrappers)
* **The Problem:** Dumping raw logs into ChatGPT causes massive token exhaustion and dangerous **hallucinations** (inventing fake IP addresses or hallucinating attack stages).
* **The SENTINEL Advantage:** **Hybrid Deterministic-to-Probabilistic Guardrails.** High-severity artifacts are first grounded against hardened Sigma and YARA rules before reaching the LLMs. The multi-agent fan-out ensures domain models stay focused on their specific telemetry.

---

## 📊 Comprehensive Feature Comparison Matrix

| Dimension / Capability | Legacy SIEM / SOAR | Cloud AI (Security Copilot) | Raw DFIR Suites (FTK, Volatility) | **SENTINEL (Our Solution)** |
| :--- | :--- | :--- | :--- | :--- |
| **Data Privacy & Air-Gap** | ⚠️ Partial (On-prem DB) | ❌ Cloud Only (WAN Egress) | ✅ Local | **✅ 100% Local & Air-Gapped** |
| **Multi-Source Ingestion** | ⚠️ Log text only | ⚠️ Proprietary telemetry | ✅ Raw binaries/RAM/PCAP | **✅ Native EVTX, PCAP, RAM, EML** |
| **Cross-Domain Correlation** | ❌ Manual by Analyst | ⚠️ Cloud Copilot Prompting | ❌ None | **✅ Autonomous LangGraph DAG** |
| **Hallucination Prevention** | N/A (Static Rules) | ⚠️ Probabilistic only | N/A (Raw Data) | **✅ Hybrid Deterministic Guardrails** |
| **Automated Threat Hunting** | ❌ Requires manual query authoring | ⚠️ Natural Language to KQL | ❌ None | **✅ Multi-Dialect (SPL, KQL, EQL)** |
| **Automated SOAR Remediation** | ⚠️ Rigid predefined playbooks | ⚠️ Guided recommendations | ❌ None | **✅ Custom Netsh, Iptables, EDR API** |
| **Threat Intel Interoperability** | ⚠️ Add-on modules | ⚠️ Closed intelligence | ❌ None | **✅ Standard STIX 2.1 JSON Bundles** |
| **Cost & Accessibility** | 💸 \$50k–\$200k/year | 💸 High per-query token cost | 💸 Expensive licenses | **🆓 Open-Source & Self-Hosted** |

---

## 🗺️ Midterm-to-Endterm Roadmap (Sprints 1–5)

To prepare for the final Endterm defense, the project follows an engineering and empirical research plan:

```
OCT 14                OCT 28                NOV 11                NOV 25                DEC 10
MIDTERM               SPRINT 1              SPRINT 2              SPRINT 3              ENDTERM DEFENSE
   │                     │                     │                     │                     │
   ▼                     ▼                     ▼                     ▼                     ▼
[Baseline] ──────► [Benchmark &] ────► [Tool-Calling] ────► [Adversary] ────► [Final Paper &]
[Working]          [Evaluation ]       [MCP Support  ]      [Emulation]        [Enterprise UI]
[System ]          [Metrics    ]       [OS Telemetry ]      [Simulation]       [Hardening    ]
```

---

### 📅 Sprint 1 (Weeks 1–2): Research Benchmarking & Quantitative Evaluation
* **Objective:** Transition from qualitative demonstrations to measurable, peer-reviewed evaluation metrics.
* **Key Tasks:**
  1. **Benchmark Against Cyber Ranges:** Curate automated evaluation pipelines against **Splunk BOTS (Boss of the SOC) v1–v3**, **DARPA Transparent Computing (TC)**, and **EVTX-ATTACK-SAMPLES**.
  2. **Quantitative Performance Metrics:**
     * **TTP Classification Precision & Recall:** Accuracy of mapped MITRE ATT&CK techniques against ground truth.
     * **IOC Extraction Accuracy:** Precision and Recall across IPs, domains, hashes, and URLs.
     * **Mean Time to Correlate (MTTC):** Compare SENTINEL's ~40-second analysis time against the human Tier-1/Tier-2 analyst baseline (~45 minutes).

---

### 📅 Sprint 2 (Weeks 3–4): Autonomous Agent Tool-Use & MCP Protocol
* **Objective:** Upgrade sub-agents from zero-shot prompting to active, interactive function-calling agents.
* **Key Tasks:**
  1. **Interactive LangChain Tool Binding:**
     * `cyberchef_decode_base64()`: Recursively deobfuscates nested PowerShell, XOR, or compressed payloads.
     * `entropy_calculator()`: Computes sliding-window Shannon entropy across packet streams.
     * `whois_dns_lookup()`: Local WHOIS/ASN resolution.
  2. **Model Context Protocol (MCP) Server Support:** Expose SENTINEL's forensic parsers and graph intelligence as an MCP server, enabling external agentic workflows to query SENTINEL directly.

---

### 📅 Sprint 3 (Weeks 5–6): Big-Data Ingestion & Linux / Cloud Telemetry
* **Objective:** Expand ingestion capabilities to enterprise Linux and multi-cloud environments.
* **Key Tasks:**
  1. **Streaming Packet Engine:** Replace in-memory Scapy `rdpcap` with a streaming generator (`pyshark` / `tshark` chunking) to ingest multi-gigabyte PCAPs without memory spikes.
  2. **Linux Auditd & Syslog Parsers:** Ingest `/var/log/audit/audit.log` and `auth.log` to detect `sudo` abuse, privilege escalation, and SSH brute-forcing.
  3. **AWS CloudTrail & Azure Activity Log Parsers:** Ingest JSON audit logs to detect cloud IAM credential compromise and S3 bucket exfiltration.

---

### 📅 Sprint 4 (Weeks 7–8): Closed-Loop Adversary Emulation (Validation Harness)
* **Objective:** Empirically prove that SENTINEL's generated defenses block real-world attacks.
* **Key Tasks:**
  1. **Atomic Red Team Integration:**
     * Automated harness triggers an Atomic Red Team technique (e.g., T1047 WMI execution).
     * Telemetry is ingested by SENTINEL.
     * SENTINEL generates firewall blocking rules and Sigma detection signatures.
     * Test harness applies the generated rule and re-runs the attack to verify **automated containment**.

---

### 📅 Sprint 5 (Weeks 9–10): Production Packaging, Paper Writing & Final Defense
* **Objective:** Finalize production distribution and academic capstone thesis.
* **Key Tasks:**
  1. **Single-Command Containerization:** Re-introduce `docker-compose up` packaging orchestrating Streamlit, Ollama, ChromaDB, and SQLite.
  2. **Academic Paper / Thesis Draft:** Complete formal IEEE/ACM conference-formatted capstone thesis: Abstract, Related Work, System Architecture, Benchmark Evaluation, and Case Studies.
