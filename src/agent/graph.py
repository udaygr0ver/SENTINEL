from langgraph.graph import StateGraph, END
from src.agent.state import AgentState
from src.agent.nodes import (
    parser_node,
    endpoint_analyst_node,
    network_analyst_node,
    memory_analyst_node,
    correlation_agent_node,
    reporter_node
)

def build_forensic_graph():
    """Builds the multi-agent LangGraph state machine."""
    workflow = StateGraph(AgentState)
    
    # 1. Ingestion
    workflow.add_node("parser", parser_node)
    
    # 2. Specialized Sub-Agents
    workflow.add_node("endpoint_agent", endpoint_analyst_node)
    workflow.add_node("network_agent", network_analyst_node)
    workflow.add_node("memory_agent", memory_analyst_node)
    
    # 3. Lead Correlation
    workflow.add_node("correlation", correlation_agent_node)
    
    # 4. Final Reporting
    workflow.add_node("reporter", reporter_node)
    
    workflow.set_entry_point("parser")
    
    # Fan-out: parser sends data to all three specialized agents
    workflow.add_edge("parser", "endpoint_agent")
    workflow.add_edge("parser", "network_agent")
    workflow.add_edge("parser", "memory_agent")
    
    # Fan-in: all three specialized agents must complete before correlation
    workflow.add_edge("endpoint_agent", "correlation")
    workflow.add_edge("network_agent", "correlation")
    workflow.add_edge("memory_agent", "correlation")
    
    workflow.add_edge("correlation", "reporter")
    workflow.add_edge("reporter", END)
    
    return workflow.compile()

if __name__ == "__main__":
    app = build_forensic_graph()
    print("Multi-Agent Graph compiled successfully.")
