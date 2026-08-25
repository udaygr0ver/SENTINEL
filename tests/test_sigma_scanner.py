from datetime import datetime, timezone

from src.parsers.sigma_scanner import evaluate_artifact_against_sigma
from src.schema import ForensicArtifact


def test_evaluate_sigma_match():
    # Setup mock rule
    rules = [{
        "title": "Suspicious Encoded PowerShell",
        "description": "Detects encoded PowerShell",
        "tags": ["attack.t1059.001"],
        "detection": {
            "selection": {
                "EventID": "4688",
                "CommandLine|contains": "powershell -enc"
            }
        }
    }]
    
    # Setup artifact that should match
    artifact = ForensicArtifact(
        timestamp=datetime.now(timezone.utc).isoformat() + "Z",
        source_type="EVTX_4688",
        host="WORKSTATION",
        user="Admin",
        details="Process started: cmd.exe /c powershell -enc JABz...",
        ioc_detected=None
    )
    
    matches = evaluate_artifact_against_sigma(artifact, rules)
    
    assert len(matches) == 1
    match = matches[0]
    assert match.source_type == "SIGMA_MATCH"
    assert match.ioc_detected == "Suspicious Encoded PowerShell"
    assert "T1059.001" in match.details
    
def test_evaluate_sigma_no_match():
    rules = [{
        "title": "Suspicious Encoded PowerShell",
        "detection": {
            "selection": {
                "EventID": "4688",
                "CommandLine|contains": "powershell -enc"
            }
        }
    }]
    
    # Different event ID
    artifact = ForensicArtifact(
        timestamp=datetime.now(timezone.utc).isoformat() + "Z",
        source_type="EVTX_4624",
        host="WORKSTATION",
        user="Admin",
        details="Logon success powershell -enc", # Even if it contains the string, EventID doesn't match
        ioc_detected=None
    )
    
    matches = evaluate_artifact_against_sigma(artifact, rules)
    assert len(matches) == 0
