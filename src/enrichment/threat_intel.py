import re

import requests


def is_ip(ioc: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc))

def is_hash(ioc: str) -> bool:
    return bool(re.match(r"^[a-fA-F0-9]{32,64}$", ioc))

def query_virustotal(ioc: str, api_key: str) -> dict:
    """Queries VirusTotal for IP, Domain, or Hash reputation."""
    if not api_key:
        return {"error": "No API Key"}
        
    url = ""
    if is_ip(ioc):
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    elif is_hash(ioc):
        url = f"https://www.virustotal.com/api/v3/files/{ioc}"
    else:
        url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
        
    headers = {"x-apikey": api_key}
    
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "link": f"https://www.virustotal.com/gui/search/{ioc}"
            }
        elif response.status_code == 404:
            return {"error": "Not Found on VT"}
        else:
            return {"error": f"API Error: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def query_abuseipdb(ioc: str, api_key: str) -> dict:
    """Queries AbuseIPDB (only valid for IPs)."""
    if not api_key:
        return {"error": "No API Key"}
        
    if not is_ip(ioc):
        return {"error": "Not an IP"}
        
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": api_key
    }
    params = {"ipAddress": ioc, "maxAgeInDays": "90"}
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=5)
        if response.status_code == 200:
            data = response.json()
            score = data.get("data", {}).get("abuseConfidenceScore", 0)
            return {
                "confidence_score": score,
                "total_reports": data.get("data", {}).get("totalReports", 0),
                "link": f"https://www.abuseipdb.com/check/{ioc}"
            }
        else:
            return {"error": f"API Error: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def enrich_iocs(iocs: list, vt_key: str, abuse_key: str) -> dict[str, dict]:
    """Takes a list of IOCs and queries external APIs, returning a mapped dictionary of results."""
    results = {}
    for ioc in set(iocs):
        if not ioc or ioc == "UNKNOWN" or ioc == "SCAN":
            continue
            
        results[ioc] = {
            "virustotal": query_virustotal(ioc, vt_key) if vt_key else None,
            "abuseipdb": query_abuseipdb(ioc, abuse_key) if abuse_key and is_ip(ioc) else None
        }
    return results
