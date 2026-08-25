import base64

from langchain_core.tools import tool

from src.kb.retriever import get_mitre_mapping


@tool
def lookup_mitre(query: str) -> str:
    """Looks up a MITRE ATT&CK technique by ID or description."""
    results = get_mitre_mapping(query)
    if not results:
        return "No matching MITRE techniques found."
    
    out = []
    for r in results:
        out.append(f"ID: {r['technique_id']} | Name: {r['name']} | Desc: {r['description']}")
    return "\n".join(out)

@tool
def decode_base64_payload(encoded_str: str) -> str:
    """Decodes a base64 encoded string commonly found in PowerShell payloads."""
    try:
        # PowerShell payloads are often UTF-16LE encoded after base64
        decoded = base64.b64decode(encoded_str)
        try:
            return decoded.decode('utf-16-le')
        except UnicodeDecodeError:
            return decoded.decode('utf-8', errors='ignore')
    except Exception as e:
        return f"Failed to decode base64: {e}"

@tool
def query_ip_reputation(ip_address: str) -> str:
    """Queries IP reputation (Mocked for this prototype)."""
    # In a real scenario, this would query VirusTotal, AbuseIPDB, etc.
    # We will mock it based on private/public IP ranges or hardcoded malicious IPs
    if ip_address.startswith("192.168.") or ip_address.startswith("10.") or ip_address.startswith("172."):
        return f"{ip_address} is a local/private IP address."
    
    return f"{ip_address} reputation: Unknown (Mocked API)"
