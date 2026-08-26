import operator
from collections.abc import Sequence
from typing import Annotated, TypedDict

from langchain_core.messages import BaseMessage

from src.schema import ForensicArtifact


class AgentState(TypedDict):
    # The file path(s) to process
    file_paths: list[str]
    
    # Selected LLM model
    llm_model: str
    
    # Raw parsed artifacts
    artifacts: list[ForensicArtifact]
    
    # Sub-agent domain summaries
    endpoint_summary: str
    network_summary: str
    memory_summary: str
    email_summary: str
    
    # Narrative timeline
    timeline: str
    
    # Final STIX / Markdown report
    report: str
    remediation_plan: str
    threat_hunt_queries: str
    
    # LLM Messages history for the correlation/reasoning node
    messages: Annotated[Sequence[BaseMessage], operator.add]
