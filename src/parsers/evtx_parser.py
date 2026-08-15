import json
import xml.etree.ElementTree as ET
from Evtx.Evtx import Evtx
from src.schema import ForensicArtifact
from datetime import datetime

# Windows Event Log namespaces
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

def extract_event_data(event_xml):
    """Parses EVTX XML string and extracts relevant fields."""
    try:
        root = ET.fromstring(event_xml)
        
        # System details
        system = root.find(f"{NS}System")
        event_id = system.find(f"{NS}EventID").text if system is not None else None
        
        time_created = system.find(f"{NS}TimeCreated")
        timestamp = time_created.attrib.get('SystemTime') if time_created is not None else datetime.utcnow().isoformat()
        
        computer = system.find(f"{NS}Computer").text if system is not None else "UNKNOWN"
        
        # Event Data details
        event_data = root.find(f"{NS}EventData")
        data_dict = {}
        if event_data is not None:
            for data in event_data.findall(f"{NS}Data"):
                name = data.attrib.get('Name')
                if name:
                    data_dict[name] = data.text

        return event_id, timestamp, computer, data_dict
    except Exception as e:
        return None, None, None, {}

def parse_evtx(file_path: str):
    """Parses an EVTX file and yields ForensicArtifact objects for specific Event IDs."""
    target_event_ids = {"4688", "4624", "4625", "7045", "4104"}
    
    artifacts = []
    try:
        with Evtx(file_path) as evtx_file:
            for record in evtx_file.records():
                event_xml = record.xml()
                event_id, timestamp, computer, data_dict = extract_event_data(event_xml)
                
                if event_id in target_event_ids:
                    details = ""
                    user = data_dict.get("SubjectUserName", "UNKNOWN")
                    ioc = None
                    
                    if event_id == "4688": # Process Creation
                        cmdline = data_dict.get("CommandLine", "")
                        proc = data_dict.get("NewProcessName", "")
                        details = f"Process: {proc} | Cmdline: {cmdline}"
                        
                    elif event_id in ["4624", "4625"]: # Logon
                        logon_type = data_dict.get("LogonType", "")
                        ip = data_dict.get("IpAddress", "")
                        user = data_dict.get("TargetUserName", user)
                        details = f"Logon Type: {logon_type} | IP: {ip}"
                        ioc = ip if ip and ip != "-" else None
                        
                    elif event_id == "7045": # Service Install
                        svc_name = data_dict.get("ServiceName", "")
                        img_path = data_dict.get("ImagePath", "")
                        details = f"Service: {svc_name} | Path: {img_path}"
                        
                    elif event_id == "4104": # PowerShell
                        script_block = data_dict.get("ScriptBlockText", "")
                        details = f"PowerShell Script: {script_block[:200]}..." # Truncate for summary
                        
                    artifact = ForensicArtifact(
                        timestamp=timestamp,
                        source_type=f"EVTX_{event_id}",
                        host=computer,
                        user=user,
                        details=details,
                        ioc_detected=ioc
                    )
                    artifacts.append(artifact)
    except Exception as e:
        print(f"Error parsing EVTX {file_path}: {e}")
        
    return artifacts

if __name__ == "__main__":
    # Test script if run directly
    import sys
    if len(sys.argv) > 1:
        res = parse_evtx(sys.argv[1])
        for a in res:
            print(a.model_dump_json(indent=2))
