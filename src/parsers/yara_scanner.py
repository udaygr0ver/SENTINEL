import os
import yara
from datetime import datetime
from src.schema import ForensicArtifact

# Determine the absolute path to the rules directory
RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "rules", "yara")

def get_compiled_rules():
    """Compiles all .yar files in the rules directory."""
    if not os.path.exists(RULES_DIR):
        return None
        
    filepaths = {}
    for filename in os.listdir(RULES_DIR):
        if filename.endswith(".yar") or filename.endswith(".yara"):
            # Namespace rules by their filename
            filepaths[filename] = os.path.join(RULES_DIR, filename)
            
    if not filepaths:
        return None
        
    try:
        rules = yara.compile(filepaths=filepaths)
        return rules
    except Exception as e:
        print(f"Error compiling YARA rules: {e}")
        return None

def scan_file(file_path: str):
    """Scans a file against compiled YARA rules and returns ForensicArtifacts."""
    artifacts = []
    
    if not os.path.exists(file_path):
        return artifacts
        
    rules = get_compiled_rules()
    if not rules:
        return artifacts
        
    try:
        matches = rules.match(file_path)
        for match in matches:
            # Extract metadata if available
            meta_desc = match.meta.get('description', 'No description')
            mitre = match.meta.get('mitre', 'Unknown')
            
            artifact = ForensicArtifact(
                timestamp=datetime.utcnow().isoformat() + "Z",
                source_type="YARA_MATCH",
                host="SCAN",
                user="SYSTEM",
                details=f"YARA Rule '{match.rule}' matched: {meta_desc} (MITRE: {mitre})",
                ioc_detected=match.rule
            )
            artifacts.append(artifact)
    except Exception as e:
        print(f"Error matching YARA rules on {file_path}: {e}")
        
    return artifacts
