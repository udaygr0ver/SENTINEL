from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class ForensicArtifact(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "timestamp": "2026-08-19T10:15:30Z",
                "source_type": "EVTX_4688",
                "host": "WORKSTATION-01",
                "user": "SYSTEM",
                "details": "powershell.exe -enc <base64 payload>",
                "ioc_detected": "192.168.1.50"
            }
        }
    )

    timestamp: str = Field(..., description="ISO 8601 timestamp of the event")
    source_type: str = Field(..., description="Source of the artifact (e.g., EVTX_4688, PCAP_DNS, MEM_PSLIST)")
    host: Optional[str] = Field(None, description="Hostname or IP address of the source")
    user: Optional[str] = Field(None, description="User associated with the event")
    details: str = Field(..., description="Details of the event (e.g., command line, DNS query, process name)")
    ioc_detected: Optional[str] = Field(None, description="Extracted Indicator of Compromise (e.g., IP, Hash, Domain)")
