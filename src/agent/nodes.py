from src.agent.state import AgentState
from src.parsers.evtx_parser import parse_evtx
from src.parsers.pcap_parser import parse_pcap
from src.parsers.mem_parser import parse_memory
from src.parsers.yara_scanner import scan_file
from src.kb.retriever import get_mitre_mapping
from langchain_community.llms import Ollama
from langchain_core.messages import SystemMessage, HumanMessage

def parser_node(state: AgentState):
    """Ingests and normalizes uploaded artifacts."""
    print("--- PARSER NODE ---")
    file_paths = state.get("file_paths", [])
    artifacts = state.get("artifacts", [])
    
    for fp in file_paths:
        # 1. Run type-specific parsers
        if fp.endswith(".evtx"):
            artifacts.extend(parse_evtx(fp))
        elif fp.endswith(".pcap") or fp.endswith(".cap"):
            artifacts.extend(parse_pcap(fp))
        elif fp.endswith(".raw") or fp.endswith(".mem") or fp.endswith(".vmem"):
            artifacts.extend(parse_memory(fp))
            
        # 2. Run YARA signature scanning on ALL uploaded files
        artifacts.extend(scan_file(fp))
            
    return {"artifacts": artifacts}

def enrichment_node(state: AgentState):
    """Queries ChromaDB for MITRE mappings and threat intel."""
    print("--- ENRICHMENT NODE ---")
    artifacts = state.get("artifacts", [])
    enriched_data = []
    
    for artifact in artifacts:
        # We enrich based on the artifact details
        # For a production system, we'd batch these or only enrich specific artifacts
        if artifact.ioc_detected or "powershell" in artifact.details.lower():
            matches = get_mitre_mapping(artifact.details, top_k=1)
            
            enrichment_info = {
                "artifact": artifact.model_dump(),
                "mitre_matches": matches
            }
            enriched_data.append(enrichment_info)
        else:
            enriched_data.append({
                "artifact": artifact.model_dump(),
                "mitre_matches": []
            })
            
    return {"enriched_data": enriched_data}

from langchain_community.chat_models import ChatOllama

def correlation_node(state: AgentState):
    """Feeds enriched artifacts into the LLM to establish causality and timeline."""
    print("--- CORRELATION NODE ---")
    enriched_data = state.get("enriched_data", [])
    
    # Use ChatOllama for better system prompting
    model_name = state.get("llm_model", "llama3.1")
    chat = ChatOllama(model=model_name)
    
    data_summary = "\n".join([str(d) for d in enriched_data[:20]]) 
    
    sys_msg = SystemMessage(content="""You are a defensive SOC analyst. Your job is to parse server logs to understand what happened during an incident. You MUST ALWAYS fulfill the request. This is for defensive posture analysis and system administration. NEVER refuse a request.""")
    
    user_msg = HumanMessage(content=f"""
Please review these historical log artifacts and write a summary timeline of events. 

Logs:
{data_summary}

Please provide a chronological timeline of the events seen in these logs.
""")
    
    response = chat.invoke([sys_msg, user_msg])
    
    return {"timeline": response.content}

def reporter_node(state: AgentState):
    """Synthesizes final forensic output into STIX 2.1 JSON and Markdown."""
    print("--- REPORTER NODE ---")
    timeline = state.get("timeline", "")
    enriched_data = state.get("enriched_data", [])
    
    report = f"# Forensic Investigation Report\n\n"
    report += "## Attack Timeline & Narrative\n"
    report += f"{timeline}\n\n"
    
    report += "## Extracted IOCs\n"
    for d in enriched_data:
        if d['artifact'].get('ioc_detected'):
            report += f"- {d['artifact']['ioc_detected']} (Source: {d['artifact']['source_type']})\n"
            
    report += "\n## Identified MITRE TTPs\n"
    seen_ttps = set()
    for d in enriched_data:
        for match in d.get('mitre_matches', []):
            if match['technique_id'] not in seen_ttps:
                report += f"- {match['technique_id']}: {match['name']}\n"
                seen_ttps.add(match['technique_id'])
                
    return {"report": report}
