# SENTINEL User Guide & Walkthrough

This guide provides end-to-end instructions for deploying SENTINEL locally, conducting an autonomous multi-source forensic investigation, navigating the 9-tab dashboard, running automated CLI evaluations, and integrating with the REST API.

---

## 💻 Prerequisites & Local Setup

SENTINEL is built for completely local, air-gapped execution. An Apple Silicon Mac (M1/M2/M3) or a machine with a dedicated GPU and 16GB+ RAM is recommended for optimal inference speed.

### Step 1: Clone the Repository
```bash
git clone https://github.com/udaygr0ver/SENTINEL.git
cd SENTINEL
```

### Step 2: Configure Python Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Step 3: Start Ollama & Pull Llama 3.1
Install [Ollama](https://ollama.ai/) if not already installed, ensure the Ollama daemon is running, and pull the default Llama 3.1 model:
```bash
ollama pull llama3.1
```
*(You can also pull `mistral` or `llama3.1:70b` if your hardware permits).*

---

## 🚀 Running the Interactive SOC Dashboard

Launch the Streamlit web dashboard:
```bash
streamlit run src/app.py
```
Open your browser and navigate to **`http://localhost:8501`**.

---

## 🔍 Conducting an Investigation (Step-by-Step)

### 1. Upload Forensic Evidence
In the **🆕 New Investigation** view, drag and drop one or more forensic evidence files into the upload zone:
* `.evtx` (Windows Event Logs)
* `.pcap` or `.cap` (Network Packet Captures)
* `.mem`, `.raw`, or `.vmem` (Memory Dumps)
* `.eml` (Phishing Email Files)

> **💡 Try the Pre-Packaged Demo Data:**
> The repository includes verified attack fixtures in the `demo_data/` folder:
> * `demo_data/phishing_attack.eml`: Spoofed Office 365 credential harvesting email with failed SPF/DKIM records.
> * `demo_data/lateral_movement.pcap`: Scapy capture containing high-entropy DNS tunneling and HTTP C2 beaconing.
> * `demo_data/security_log.evtx`: Real Windows Event Log containing suspicious process creations and logon sessions.

### 2. Configure Investigation Settings (Sidebar)
* **LLM Model:** Select `llama3.1` (default), `mistral`, or larger parameter variants.
* **RAG Top-K Results:** Adjust the number of MITRE ATT&CK techniques retrieved per suspicious event (default: 3).
* **Threat Intel APIs (Optional):** Enter your VirusTotal and AbuseIPDB API keys to enable real-time reputation queries for extracted IOCs.

### 3. Execute Analysis
Click **🚀 Run Analysis**. The real-time progress bar will track the 7-agent pipeline:
$$\text{Parser} \rightarrow \text{Domain Specialists} \rightarrow \text{Lead SOC Correlation} \rightarrow \text{SOAR} \rightarrow \text{Threat Hunter} \rightarrow \text{Ticketing}$$

---

## 📊 Navigating the 9-Tab Results Dashboard

Once the investigation completes, SENTINEL presents a comprehensive multi-tab SOC interface:

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│ [📊 Timeline] [🔗 Attack Graph] [🤖 Agent Summaries] [🎯 IOCs] [🌍 Threat Intel] [🛡️ SOAR] ...  │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### Tab 1: 📊 Timeline
* **Plotly Interactive Gantt Chart:** Displays timestamped forensic events across all source domains. Hover over data points to inspect raw command lines, URLs, and process names.
* **AI-Generated Narrative:** The Lead SOC Analyst's correlated, chronological intrusion story detailing the initial access vector through to exfiltration.

### Tab 2: 🔗 Attack Graph
* **Force-Directed Network Visualization:** Built with `streamlit-agraph` / Vis.js.
* **Nodes:**
  * 🔵 **Hexagons (Hosts):** Compromised workstations or servers.
  * 💎 **Diamonds (Users):** User accounts identified in logon or process events.
  * ⭐ **Stars (IOCs):** Malicious IPs, domains, hashes, and URLs.
  * 🟡 **Circles (Global):** Global scan or signature detections.
* **Physics Engine:** Tuned repulsive physics allow dragging nodes and inspecting relationship edges without text overlap.

### Tab 3: 🤖 Agent Summaries
A 2-column comparative layout displaying the individual intelligence summaries from each specialized agent:
* **💻 Endpoint Analyst:** Process anomalies, Sigma rule hits, privilege escalation attempts.
* **🌐 Network Analyst:** DNS tunneling anomalies, C2 beacon intervals, exfiltration targets.
* **🧠 Memory Analyst:** Volatility RAM analysis and injected code detection.
* **📧 Email Analyst:** Spoofed sender headers, failed SPF/DKIM records, and phishing lure tactics.

### Tab 4: 🎯 IOCs & Evidence
* **IOC Badges:** Extracted indicators of compromise ready for copying into firewall or proxy blocklists.
* **MITRE ATT&CK TTP Badges:** Visual tags (e.g., `⚔️ T1059.001`, `⚔️ T1071.004`) dynamically extracted from Sigma and YARA findings.
* **Full Evidence Log:** Chronological table of all parsed `ForensicArtifact` objects with source type, user, host, and details.

### Tab 5: 🌍 Threat Intel
* Real-time reputation lookups for extracted IOCs against **VirusTotal** (malicious vs. clean engine detections) and **AbuseIPDB** (confidence of abuse percentage).
* Direct deep-links to external intelligence pages.

### Tab 6: 🛡️ SOAR Remediation
* **Network Containment:** Ready-to-execute Windows `netsh advfirewall` and Linux `iptables` rules to block malicious IPs and C2 domains.
* **EDR Host Isolation:** API payloads for CrowdStrike Falcon and Microsoft Defender for Endpoint.
* **Custom Detection Signatures:** Auto-authored Sigma and YARA rules to detect recurring instances of the attack.
* **Download Button:** Export the full remediation plan as Markdown.

### Tab 7: 🔍 Threat Hunting
* **Splunk SPL:** Multi-index hunting queries scanning for observed process executions, C2 URLs, and beacon intervals.
* **Microsoft Sentinel KQL:** Queries joining `DeviceProcessEvents` and `DeviceNetworkEvents`.
* **Elastic EQL:** Process lineage queries tracing child-to-parent execution chains.
* **Download Button:** Export queries as Markdown.

### Tab 8: 🎫 SOC Ticket
* Standardized, syntax-highlighted **Jira / ServiceNow Incident API JSON** payload with mapped incident priority, summary, timeline, and remediation recommendations.
* **Download Button:** Export ticket payload as JSON.

### Tab 9: 📋 Report & STIX 2.1
* **Full Forensic Report:** Complete executive summary and technical analysis available for one-click Markdown download.
* **STIX 2.1 Bundle:** Machine-readable OASIS Cyber Threat Intelligence JSON bundle containing `indicator`, `malware`, and `observed-data` objects for downstream TIP/SOAR ingestion.

---

## 📂 Reviewing Past Cases (Case History)

In the sidebar, switch from **🆕 New Investigation** to **📂 Case History**:
* View all previous investigations stored in the local SQLite database (`data/sentinel.db`).
* Click **📂 View Report** on any case to instantly restore the full dashboard, timeline, attack graph, and IOCs in milliseconds with **zero LLM re-computation**.

---

## ⚡ Headless Automated CLI Demo (`run_demo.py`)

If you want to evaluate the complete multi-agent pipeline from the terminal without opening a browser:

```bash
python run_demo.py
```

This runs the complete 7-agent pipeline across the sample EML, PCAP, and EVTX files in `demo_data/` and saves the full report to **`demo_output.md`**.

---

## 🌐 REST API Usage (FastAPI)

For enterprise automation, SENTINEL exposes a full REST API:

```bash
uvicorn src.api:app --reload --port 8000
```

### Endpoints
* `POST /api/v1/analyze`: Upload evidence files and trigger background multi-agent investigation.
* `GET /api/v1/cases`: Retrieve a list of all historical forensic cases.
* `GET /api/v1/cases/{case_id}`: Retrieve detailed state, timeline, report, and IOCs for a specific case.
* `GET /health`: Healthcheck endpoint.

Visit **`http://localhost:8000/docs`** for interactive Swagger/OpenAPI documentation.

---

## 🧪 Running Unit Tests

Run the full pytest suite to verify all forensic parsers and rule engines:
```bash
pytest -v
```
All 10 tests should pass cleanly in under 1 second.
