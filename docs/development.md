# Extending SENTINEL: Developer Guide

SENTINEL is built with modularity as a first-class engineering principle. This guide details how to add custom detection rules, implement new forensic parsers, extend LangGraph agent nodes, and run the automated test suite.

---

## 📁 Codebase Layout

```
src/
├── agent/
│   ├── graph.py          # LangGraph DAG compiler and node edge routing
│   ├── nodes.py          # Implementation of all 7 specialized sub-agent nodes
│   ├── state.py          # AgentState TypedDict schema definition
│   └── tools.py          # Reusable forensic tools (decoders, entropy, RAG)
├── db/
│   └── case_manager.py   # SQLite persistence layer and CRUD operations
├── enrichment/
│   └── threat_intel.py   # VirusTotal & AbuseIPDB client connectors
├── kb/
│   ├── ingest_mitre.py   # MITRE ATT&CK STIX 2.1 embedding ingestion
│   └── retriever.py      # ChromaDB vector similarity search interface
├── parsers/              # Native forensic parser suite
│   ├── eml_parser.py     # RFC 5322 email & phishing parser
│   ├── evtx_parser.py    # Windows EVTX XML parser
│   ├── mem_parser.py     # Volatility 3 RAM parser
│   ├── pcap_parser.py    # Scapy packet & DNS entropy parser
│   ├── sigma_scanner.py  # In-memory Sigma YAML rule evaluator
│   └── yara_scanner.py   # Compiled YARA signature scanner
├── reporting/
│   ├── graph_viz.py      # Vis.js attack relationship graph renderer
│   ├── stix_exporter.py  # OASIS STIX 2.1 JSON bundle generator
│   └── timeline_viz.py   # Plotly Gantt chronological timeline generator
├── api.py                # FastAPI REST interface
├── app.py                # Streamlit SOC dashboard
└── schema.py             # Normalized ForensicArtifact Pydantic model
```

---

## 🛡️ Adding Custom YARA & Sigma Rules

SENTINEL's parser node automatically discovers and compiles rules located in the `rules/` directory.

### 1. Adding a YARA Rule
Drop any `.yar` or `.yara` file into `rules/yara/`. The engine compiles all files in the directory on startup.

**Example: `rules/yara/suspicious_dropper.yar`**
```yara
rule Suspicious_Powershell_Dropper {
    meta:
        description = "Detects hidden download cradles in script files or memory"
        author = "SENTINEL SOC"
        mitre = "T1059.001"
    strings:
        $cradle1 = "Net.WebClient" ascii nocase
        $cradle2 = "DownloadString" ascii nocase
        $cradle3 = "IEX" ascii nocase
    condition:
        all of them
}
```

### 2. Adding a Sigma Rule
Drop any `.yml` or `.yaml` file into `rules/sigma/`.

**Example: `rules/sigma/process_injection.yml`**
```yaml
title: Potential Process Injection via CreateRemoteThread
id: e4b23c91-4d1a-4f9e-a89e-b9b9c9d9e9e9
description: Detects process injection attempts using suspicious utility binaries.
status: experimental
author: SENTINEL Threat Intel
tags:
    - attack.t1055
    - attack.privilege_escalation
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        EventID: 4688
        CommandLine|contains: 'inject.exe'
    condition: selection
level: critical
```

---

## 🔌 Writing a New Forensic Parser

To add support for a new evidence format (e.g., Linux Auditd, Zeek logs, or AWS CloudTrail):

### Step 1: Create the Parser in `src/parsers/`
Implement a function that accepts the evidence file path and returns a list of normalized `ForensicArtifact` objects:

```python
# src/parsers/auditd_parser.py
import re
from datetime import datetime, timezone
from typing import List
from src.schema import ForensicArtifact

def parse_auditd(file_path: str) -> List[ForensicArtifact]:
    artifacts = []
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if "type=EXECVE" in line:
                # Extract command and timestamp
                artifacts.append(
                    ForensicArtifact(
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        source_type="LINUX_AUDITD",
                        host="linux-server",
                        user="root",
                        details=f"Execve event: {line.strip()}",
                        ioc_detected=None
                    )
                )
    return artifacts
```

### Step 2: Register in `src/agent/nodes.py`
In `parser_node()`, wire the file extension to your new parser:
```python
elif fp.endswith(".audit") or fp.endswith(".log"):
    artifacts.extend(parse_auditd(fp))
```

---

## 🤖 Adding or Modifying LangGraph Agents

The multi-agent state is defined in `src/agent/state.py` using `AgentState(TypedDict)`:

```python
class AgentState(TypedDict):
    file_paths: List[str]
    llm_model: str
    artifacts: List[ForensicArtifact]
    endpoint_summary: str
    network_summary: str
    memory_summary: str
    email_summary: str
    timeline: str
    report: str
    remediation_plan: str
    threat_hunt_queries: str
    jira_ticket: str
    messages: Annotated[Sequence[BaseMessage], operator.add]
```

### Creating a New Agent Node
1. Define the node function in `src/agent/nodes.py`:
```python
def cloud_analyst_node(state: AgentState):
    """Analyzes AWS CloudTrail or Azure Activity Logs."""
    chat = get_llm(state)
    sys_msg = SystemMessage(content="You are an expert Cloud Security Analyst...")
    user_msg = HumanMessage(content=f"Analyze these cloud artifacts: {state['artifacts']}")
    response = chat.invoke([sys_msg, user_msg])
    return {"cloud_summary": response.content}
```

2. Register the node in `src/agent/graph.py`:
```python
workflow.add_node("cloud_agent", cloud_analyst_node)
workflow.add_edge("parser", "cloud_agent")
workflow.add_edge("cloud_agent", "correlation")
```

---

## 🧪 Testing Guidelines

SENTINEL enforces unit testing for all parsers and rule evaluations.

### Running Tests
```bash
pytest -v
```

### Adding a Unit Test
Create tests in `tests/test_<component>.py`:
```python
def test_parse_custom_log(tmp_path):
    log_file = tmp_path / "test.log"
    log_file.write_text("type=EXECVE a0=sudo a1=bash\n")
    artifacts = parse_auditd(str(log_file))
    assert len(artifacts) == 1
    assert artifacts[0].source_type == "LINUX_AUDITD"
```

All contributions must pass `pytest` with zero warnings before merging.
