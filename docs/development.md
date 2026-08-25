# Extending SENTINEL

SENTINEL's parser architecture is designed to be highly modular. You can easily add support for new log types (e.g., Linux Syslog, AWS CloudTrail) or custom threat intelligence rules.

## Adding Custom YARA / Sigma Rules

To deploy custom deterministic detections, simply drop your rules into the respective folders:

- **YARA**: Add `.yar` or `.yara` files to `rules/yara/`. The engine will auto-compile them on the next run.
- **Sigma**: Add `.yml` or `.yaml` files to `rules/sigma/`.

## Writing a New Parser

To add a new parser (e.g., `syslog_parser.py`):

1. Create a script in `src/parsers/`
2. Define a function that accepts a file path and returns a list of `ForensicArtifact` objects.
```python
from src.schema import ForensicArtifact
from datetime import datetime

def parse_syslog(file_path: str) -> list:
    artifacts = []
    # Your parsing logic here
    artifact = ForensicArtifact(
        timestamp=datetime.utcnow().isoformat() + "Z",
        source_type="SYSLOG_SSH",
        host="ubuntu-server",
        user="root",
        details="Failed password for root from 192.168.1.5",
        ioc_detected="192.168.1.5"
    )
    artifacts.append(artifact)
    return artifacts
```
3. Update `src/agent/graph.py` to route the new file extension to the appropriate analyst agent.
