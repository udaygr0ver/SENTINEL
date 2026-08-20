import operator
from typing import TypedDict, Annotated, Sequence
from langchain_core.messages import BaseMessage
from src.schema import ForensicArtifact

class AgentState(TypedDict):
    # The file path(s) to process
    file_paths: list[str]
    
    # Raw parsed artifacts
    artifacts: list[ForensicArtifact]
    
    # Enriched artifacts (with MITRE mappings)
    enriched_data: list[dict]
    
    # Narrative timeline
    timeline: str
    
    # Final STIX / Markdown report
    report: str
    
    # LLM Messages history for the correlation/reasoning node
    messages: Annotated[Sequence[BaseMessage], operator.add]
