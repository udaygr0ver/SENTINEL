from langgraph.graph import StateGraph, END
from src.agent.state import AgentState
from src.agent.nodes import parser_node, enrichment_node, correlation_node, reporter_node

def build_forensic_graph():
    """Builds and compiles the LangGraph state machine."""
    workflow = StateGraph(AgentState)
    
    workflow.add_node("parser", parser_node)
    workflow.add_node("enrichment", enrichment_node)
    workflow.add_node("correlation", correlation_node)
    workflow.add_node("reporter", reporter_node)
    
    workflow.set_entry_point("parser")
    
    workflow.add_edge("parser", "enrichment")
    workflow.add_edge("enrichment", "correlation")
    workflow.add_edge("correlation", "reporter")
    workflow.add_edge("reporter", END)
    
    return workflow.compile()

if __name__ == "__main__":
    app = build_forensic_graph()
    print("Graph compiled successfully.")
