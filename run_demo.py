import asyncio
import os
import sys

from src.agent.graph import build_forensic_graph
from src.agent.state import AgentState

sys.path.append(os.path.dirname(os.path.abspath(__file__)))


async def run_demo():
    demo_files = [
        "demo_data/phishing_attack.eml",
        "demo_data/lateral_movement.pcap",
        "demo_data/security_log.evtx",
    ]
    
    print(f"📁 Processing multi-source forensic demo artifacts: {demo_files}")
    
    initial_state = AgentState(
        file_paths=demo_files,
        llm_model="llama3.1",
        artifacts=[],
        endpoint_summary="",
        network_summary="",
        memory_summary="",
        email_summary="",
        timeline="",
        report="",
        remediation_plan="",
        threat_hunt_queries="",
        jira_ticket="",
        messages=[],
    )
    
    print("⚙️ Initializing Multi-Agent LangGraph Pipeline...")
    graph = build_forensic_graph()
    
    print("🚀 Running Agents (Parser → Domain Analysts → Lead SOC → SOAR → Threat Hunter → Ticketing)...")
    final_state = await graph.ainvoke(initial_state)
    
    with open("demo_output.md", "w") as f:
        f.write("# 🛡️ SENTINEL Multi-Agent Investigation Demo Output\n\n")
        f.write("## 📧 Email / Phishing Analyst Findings\n")
        f.write(final_state.get("email_summary", "") + "\n\n")
        f.write("## 💻 Endpoint Analyst Findings\n")
        f.write(final_state.get("endpoint_summary", "") + "\n\n")
        f.write("## 🌐 Network Analyst Findings\n")
        f.write(final_state.get("network_summary", "") + "\n\n")
        f.write("## 🧠 Memory Analyst Findings\n")
        f.write(final_state.get("memory_summary", "") + "\n\n")
        f.write("## 📊 Incident Timeline & Narrative\n")
        f.write(final_state.get("timeline", "") + "\n\n")
        f.write("## 🔍 Threat Hunting Queries (Splunk SPL / KQL / EQL)\n")
        f.write(final_state.get("threat_hunt_queries", "") + "\n\n")
        f.write("## 🛡️ SOAR Remediation Plan\n")
        f.write(final_state.get("remediation_plan", "") + "\n\n")
        f.write("## 🎫 Automated SOC Ticket (Jira / ServiceNow API)\n")
        f.write("```json\n" + final_state.get("jira_ticket", "") + "\n```\n")
        
    print(f"✅ Demo completed! Parsed {len(final_state.get('artifacts', []))} artifacts.")
    print("📄 Output saved to demo_output.md")


if __name__ == "__main__":
    asyncio.run(run_demo())
