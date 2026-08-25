import json
import uuid
from datetime import datetime

def generate_stix_bundle(enriched_data, report_text):
    """Generates a STIX 2.1 JSON bundle from the findings."""
    objects = []
    
    # Create the report object
    report_id = f"report--{uuid.uuid4()}"
    report_obj = {
        "type": "report",
        "id": report_id,
        "spec_version": "2.1",
        "created": datetime.utcnow().isoformat() + "Z",
        "modified": datetime.utcnow().isoformat() + "Z",
        "name": "Autonomous Forensic Agent Investigation Report",
        "description": report_text,
        "published": datetime.utcnow().isoformat() + "Z",
        "object_refs": []
    }
    
    # Create indicators for IOCs
    for artifact in enriched_data:
        ioc = artifact.ioc_detected
        if ioc:
            indicator_id = f"indicator--{uuid.uuid4()}"
            indicator = {
                "type": "indicator",
                "id": indicator_id,
                "spec_version": "2.1",
                "created": datetime.utcnow().isoformat() + "Z",
                "modified": datetime.utcnow().isoformat() + "Z",
                "name": f"Malicious IP/Domain: {ioc}",
                "pattern_type": "stix",
                "pattern": f"[ipv4-addr:value = '{ioc}']" if "." in ioc and not ioc.isalpha() else f"[domain-name:value = '{ioc}']",
                "valid_from": datetime.utcnow().isoformat() + "Z"
            }
            objects.append(indicator)
            report_obj["object_refs"].append(indicator_id)
            
    objects.append(report_obj)
    
    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects
    }
    
    return json.dumps(bundle, indent=2)
