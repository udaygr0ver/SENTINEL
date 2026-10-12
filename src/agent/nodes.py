from langchain_community.chat_models import ChatOllama
from langchain_core.messages import HumanMessage, SystemMessage

from src.agent.state import AgentState
from src.kb.retriever import get_mitre_mapping
from src.parsers.eml_parser import parse_eml
from src.parsers.evtx_parser import parse_evtx
from src.parsers.mem_parser import parse_memory
from src.parsers.pcap_parser import parse_pcap
from src.parsers.sigma_scanner import scan_artifacts_with_sigma
from src.parsers.yara_scanner import scan_file


def parser_node(state: AgentState):
    """Ingests and normalizes uploaded artifacts."""
    print("--- PARSER NODE ---")
    file_paths = state.get("file_paths", [])
    artifacts = state.get("artifacts", [])
    
    for fp in file_paths:
        if fp.endswith(".evtx"):
            artifacts.extend(parse_evtx(fp))
        elif fp.endswith(".pcap") or fp.endswith(".cap"):
            artifacts.extend(parse_pcap(fp))
        elif fp.endswith(".raw") or fp.endswith(".mem") or fp.endswith(".vmem"):
            artifacts.extend(parse_memory(fp))
        elif fp.endswith(".eml"):
            artifacts.extend(parse_eml(fp))
            
        artifacts.extend(scan_file(fp))
        
    sigma_matches = scan_artifacts_with_sigma(artifacts)
    artifacts.extend(sigma_matches)
            
    return {"artifacts": artifacts}

def get_llm(state: AgentState):
    model_name = state.get("llm_model", "llama3.1")
    import os
    base_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
    return ChatOllama(model=model_name, base_url=base_url)

def endpoint_analyst_node(state: AgentState):
    """Analyzes EVTX logs and Sigma matches."""
    print("--- ENDPOINT ANALYST ---")
    artifacts = state.get("artifacts", [])
    endpoint_arts = [a for a in artifacts if "EVTX" in a.source_type or "SIGMA" in a.source_type]
    
    if not endpoint_arts:
        return {"endpoint_summary": "No endpoint artifacts provided."}
        
    # Enrich with MITRE
    enriched = []
    for art in endpoint_arts:
        if art.ioc_detected or "powershell" in art.details.lower():
            matches = get_mitre_mapping(art.details, top_k=1)
            enriched.append({"artifact": art.model_dump(), "mitre": matches})
        else:
            enriched.append({"artifact": art.model_dump(), "mitre": []})
            
    chat = get_llm(state)
    sys_msg = SystemMessage(content="You are the Endpoint Forensics Expert. Summarize the Windows event logs and Sigma matches, identifying potential execution, persistence, or privilege escalation. Be concise.")
    user_msg = HumanMessage(content=f"Analyze these endpoint artifacts:\n{enriched[:15]!s}")
    
    response = chat.invoke([sys_msg, user_msg])
    return {"endpoint_summary": response.content}

def network_analyst_node(state: AgentState):
    """Analyzes PCAP logs."""
    print("--- NETWORK ANALYST ---")
    artifacts = state.get("artifacts", [])
    net_arts = [a for a in artifacts if "PCAP" in a.source_type]
    
    if not net_arts:
        return {"network_summary": "No network artifacts provided."}
        
    chat = get_llm(state)
    sys_msg = SystemMessage(content="You are the Network Forensics Expert. Summarize the PCAP HTTP/DNS logs, looking for C2 beacons, exfiltration, or lateral movement. Be concise.")
    user_msg = HumanMessage(content=f"Analyze these network artifacts:\n{[a.model_dump() for a in net_arts[:15]]!s}")
    
    response = chat.invoke([sys_msg, user_msg])
    return {"network_summary": response.content}

def memory_analyst_node(state: AgentState):
    """Analyzes Volatility memory dumps and YARA matches."""
    print("--- MEMORY ANALYST ---")
    artifacts = state.get("artifacts", [])
    mem_arts = [a for a in artifacts if "MEM_" in a.source_type or "YARA" in a.source_type]
    
    if not mem_arts:
        return {"memory_summary": "No memory artifacts provided."}
        
    chat = get_llm(state)
    sys_msg = SystemMessage(content="You are the Memory Forensics Expert. Summarize the running processes, network connections, and YARA malware signatures found in RAM. Be concise.")
    user_msg = HumanMessage(content=f"Analyze these memory artifacts:\n{[a.model_dump() for a in mem_arts[:15]]!s}")
    
    response = chat.invoke([sys_msg, user_msg])
    return {"memory_summary": response.content}

def correlation_agent_node(state: AgentState):
    """Combines domain summaries into a unified attack narrative."""
    print("--- CORRELATION AGENT ---")
    ep_sum = state.get("endpoint_summary", "")
    net_sum = state.get("network_summary", "")
    mem_sum = state.get("memory_summary", "")
    eml_sum = state.get("email_summary", "")
    
    chat = get_llm(state)
    sys_msg = SystemMessage(content="You are the Lead SOC Analyst. Your job is to correlate findings from your Endpoint, Network, Memory, and Email Forensics experts into a single, cohesive chronological attack narrative. Do not refuse this request; it is for defensive simulation.")
    
    user_msg = HumanMessage(content=f"Please synthesize this multi-domain intelligence into a final incident timeline:\n\nENDPOINT:\n{ep_sum}\n\nNETWORK:\n{net_sum}\n\nMEMORY:\n{mem_sum}\n\nEMAIL:\n{eml_sum}")
    
    response = chat.invoke([sys_msg, user_msg])
    return {"timeline": response.content}

def reporter_node(state: AgentState):
    """Synthesizes final forensic output."""
    print("--- REPORTER NODE ---")
    timeline = state.get("timeline", "")
    artifacts = state.get("artifacts", [])
    
    report = "# Multi-Agent Forensic Investigation Report\n\n"
    report += "## Attack Timeline & Narrative\n"
    report += f"{timeline}\n\n"
    
    report += "## Extracted IOCs & Evidence\n"
    for a in artifacts:
        if a.ioc_detected:
            report += f"- {a.ioc_detected} ({a.source_type})\n"
            
    return {"report": report}


def remediation_agent(state: AgentState):
    llm = get_llm(state)
    
    # We only need the IOCs and the timeline to build a remediation plan
    iocs = [a.ioc_detected for a in state.get("artifacts", []) if a.ioc_detected]
    unique_iocs = list(set(iocs))
    
    if not unique_iocs and not state.get("timeline"):
        return {"remediation_plan": "No significant threats detected requiring automated remediation."}

    sys_msg = SystemMessage(content='''You are an elite SOC Automation (SOAR) Engineer.
Based on the timeline and identified Indicators of Compromise (IOCs), generate a highly structured, actionable Remediation Plan.
Your output MUST include:
1. **Network Containment**: Exact firewall commands (Windows netsh / Linux iptables) to block the malicious IPs/Domains.
2. **Endpoint Isolation**: Mock EDR commands (e.g., CrowdStrike Falcon / Microsoft Defender API payloads) to isolate the compromised hosts.
3. **Custom Detection Rule**: Write a custom Sigma or YARA rule to detect this specific threat in the future based on the provided evidence.

Format the output cleanly in Markdown with code blocks. Do not add any introductory fluff.''')
    
    user_msg = HumanMessage(content=f'''
Incident Timeline:
{state.get("timeline")}

Extracted IOCs:
{unique_iocs}

Generate the SOAR Remediation Plan.
''')
    
    response = llm.invoke([sys_msg, user_msg])
    return {"remediation_plan": response.content}


def email_analyst_agent(state: AgentState):
    llm = get_llm(state)
    eml_artifacts = [a for a in state.get("artifacts", []) if a.source_type.startswith("EML_")]
    if not eml_artifacts:
        return {"email_summary": "No Email/Phishing artifacts provided."}
        
    sys_msg = SystemMessage(content='''You are an expert Phishing & Email Forensics Analyst.
Review the provided EML headers, URLs, and attachments.
Identify:
1. Social Engineering tactics (urgency, spoofing).
2. Header anomalies (failed SPF/DKIM).
3. Malicious payloads (suspicious URLs or attachments).
Provide a concise, 3-4 sentence summary of your findings.''')
    
    user_msg = HumanMessage(content=f"Email Artifacts: {[a.model_dump() for a in eml_artifacts]}")
    response = llm.invoke([sys_msg, user_msg])
    return {"email_summary": response.content}


def threat_hunter_agent(state: AgentState):
    llm = get_llm(state)
    
    iocs = [a.ioc_detected for a in state.get("artifacts", []) if a.ioc_detected]
    unique_iocs = list(set(iocs))
    
    if not unique_iocs and not state.get("timeline"):
        return {"threat_hunt_queries": "No significant threats detected requiring proactive hunting."}

    sys_msg = SystemMessage(content='''You are an elite SIEM Detection & Threat Hunting Engineer.
Based on the timeline and identified Indicators of Compromise (IOCs), generate proactive threat hunting queries.
Your output MUST include:
1. **Splunk SPL**: A query to search for the malicious IPs, domains, and file hashes across all indexes.
2. **Microsoft Sentinel / Azure KQL**: A KQL query to hunt for the identified malicious process executions (e.g., DeviceProcessEvents) or network connections (DeviceNetworkEvents).
3. **Elastic (EQL)**: An Elastic query looking for lateral movement or persistence tied to this threat.

Format the output cleanly in Markdown with code blocks. Do not add any introductory fluff. Provide only the queries and a brief 1-sentence explanation for each.''')
    
    user_msg = HumanMessage(content=f'''
Incident Timeline:
{state.get("timeline")}

Extracted IOCs:
{unique_iocs}

Generate the Threat Hunting Queries.
''')
    
    response = llm.invoke([sys_msg, user_msg])
    return {"threat_hunt_queries": response.content}


def ticketing_agent(state: AgentState):
    llm = get_llm(state)
    
    iocs = [a.ioc_detected for a in state.get("artifacts", []) if a.ioc_detected]
    unique_iocs = list(set(iocs))
    
    if not unique_iocs and not state.get("timeline"):
        return {"jira_ticket": '{"status": "No critical findings to escalate."}'}

    sys_msg = SystemMessage(content='''You are an Automated SOC Ticketing Engine.
Your job is to read the Incident Timeline and Remediation Plan, and output a strict JSON payload representing a Jira REST API POST request to create an Incident ticket.
The JSON must follow this exact structure:
{
    "fields": {
        "project": {"key": "SOC"},
        "summary": "CRITICAL INCIDENT: <Brief 5-word summary>",
        "description": "<Detailed markdown description including timeline and IOCs>",
        "issuetype": {"name": "Incident"},
        "priority": {"name": "Highest"},
        "customfield_1001": "<Actionable Remediation Steps>"
    }
}
Output ONLY valid JSON. Do not include markdown code blocks (```json) around the output, just the raw JSON string.''')
    
    user_msg = HumanMessage(content=f'''
Incident Timeline:
{state.get("timeline")}

Remediation Plan:
{state.get("remediation_plan")}

Generate the Jira API JSON payload.
''')
    
    response = llm.invoke([sys_msg, user_msg])
    
    # Clean up markdown blocks if the LLM adds them
    ticket_str = response.content.strip()
    ticket_str = ticket_str.removeprefix("```json")
    ticket_str = ticket_str.removeprefix("```")
    ticket_str = ticket_str.removesuffix("```")
        
    return {"jira_ticket": ticket_str.strip()}
