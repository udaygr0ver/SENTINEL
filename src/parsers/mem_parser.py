import json
import os
import subprocess
from datetime import datetime, timezone

from src.schema import ForensicArtifact


def run_volatility(file_path: str, plugin: str):
    """Runs Volatility 3 CLI and returns parsed JSON output."""
    cmd = [
        "vol", 
        "-f", file_path, 
        "-r", "json",
        plugin
    ]
    try:
        # Note: 'vol' must be in PATH, which it is if installed in venv
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0 and result.stdout:
            # Volatility JSON output may have leading info logs before the array
            # We try to find the start of the JSON array
            out = result.stdout
            idx = out.find('[')
            if idx != -1:
                return json.loads(out[idx:])
    except Exception as e:
        print(f"Error running volatility plugin {plugin}: {e}")
    return []

def parse_memory(file_path: str):
    """Wraps Volatility 3 to extract pslist, netscan, and malfind artifacts."""
    artifacts = []
    
    if not os.path.exists(file_path):
        return artifacts

    # 1. PSList
    print(f"Running windows.pslist on {file_path}...")
    pslist_data = run_volatility(file_path, "windows.pslist")
    for row in pslist_data:
        # Depending on Vol3 JSON structure, usually it's a list of dicts
        # e.g., {"PID": 4, "ImageFileName": "System"} 
        # Actually Vol3 returns a complex tree in JSON. We'll simplify extraction.
        # Format is typically [{"__children": [], "PID": 123, ...}]
        pid = row.get("PID", "")
        name = row.get("ImageFileName", "")
        
        artifact = ForensicArtifact(
            timestamp=datetime.now(timezone.utc).isoformat() + "Z", # Memory dumps lack per-process timestamp easily accessible sometimes
            source_type="MEM_PSLIST",
            host="MEMORY_IMAGE",
            user="UNKNOWN",
            details=f"Process: {name} (PID: {pid})",
            ioc_detected=None
        )
        artifacts.append(artifact)
        
    # 2. Netscan
    print(f"Running windows.netscan on {file_path}...")
    netscan_data = run_volatility(file_path, "windows.netscan")
    for row in netscan_data:
        proto = row.get("Protocol", "")
        local = row.get("LocalAddr", "")
        foreign = row.get("ForeignAddr", "")
        state = row.get("State", "")
        pid = row.get("Owner", "")
        
        ioc = foreign if foreign and foreign not in ["0.0.0.0", "::", "*"] else None
        
        artifact = ForensicArtifact(
            timestamp=datetime.now(timezone.utc).isoformat() + "Z",
            source_type="MEM_NETSCAN",
            host="MEMORY_IMAGE",
            user="UNKNOWN",
            details=f"Netscan: {proto} {local} -> {foreign} [{state}] (PID: {pid})",
            ioc_detected=ioc
        )
        artifacts.append(artifact)
        
    # 3. Malfind
    print(f"Running windows.malfind on {file_path}...")
    malfind_data = run_volatility(file_path, "windows.malfind")
    for row in malfind_data:
        pid = row.get("PID", "")
        name = row.get("Process", "")
        
        artifact = ForensicArtifact(
            timestamp=datetime.now(timezone.utc).isoformat() + "Z",
            source_type="MEM_MALFIND",
            host="MEMORY_IMAGE",
            user="UNKNOWN",
            details=f"Malfind Hit: Process {name} (PID: {pid}) contains potentially injected code.",
            ioc_detected=None # Could extract hex bytes but keeping it simple
        )
        artifacts.append(artifact)
        
    return artifacts

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        res = parse_memory(sys.argv[1])
        for a in res[:5]:
            print(a.model_dump_json(indent=2))
