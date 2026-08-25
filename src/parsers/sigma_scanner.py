import os
from datetime import datetime, timezone

import yaml

from src.schema import ForensicArtifact

RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "rules", "sigma")

def load_sigma_rules():
    """Loads all YAML files from the rules/sigma directory."""
    rules = []
    if not os.path.exists(RULES_DIR):
        return rules
        
    for filename in os.listdir(RULES_DIR):
        if filename.endswith(".yml") or filename.endswith(".yaml"):
            try:
                with open(os.path.join(RULES_DIR, filename), 'r') as f:
                    rule = yaml.safe_load(f)
                    rules.append(rule)
            except Exception as e:
                print(f"Error loading Sigma rule {filename}: {e}")
    return rules

def evaluate_artifact_against_sigma(artifact: ForensicArtifact, rules: list):
    """
    Naively evaluates a ForensicArtifact against loaded Sigma rules.
    This is a simplified Sigma engine designed for demonstrating deterministic matching.
    """
    matches = []
    # Only evaluate EVTX artifacts for Sigma
    if not artifact.source_type.startswith("EVTX_"):
        return matches
        
    extracted_event_id = artifact.source_type.split("_")[-1]
    
    for rule in rules:
        try:
            # We only support 'selection' logic for this MVP scanner
            selection = rule.get("detection", {}).get("selection", {})
            
            # Check EventID if specified in the rule
            rule_event_id = selection.get("EventID")
            if rule_event_id and str(rule_event_id) != extracted_event_id:
                continue
                
            # Check for keyword matches in the artifact details
            is_match = False
            for key, value in selection.items():
                if "contains" in key:
                    if value.lower() in artifact.details.lower():
                        is_match = True
                        break
                elif key != "EventID":
                    # Exact fallback match check
                    if str(value).lower() in artifact.details.lower():
                        is_match = True
                        break
            
            if is_match:
                mitre_tags = [t.replace("attack.", "").upper() for t in rule.get("tags", []) if t.startswith("attack.")]
                mitre_str = ", ".join(mitre_tags) if mitre_tags else "Unknown"
                
                match_artifact = ForensicArtifact(
                    timestamp=datetime.now(timezone.utc).isoformat() + "Z",
                    source_type="SIGMA_MATCH",
                    host=artifact.host,
                    user=artifact.user,
                    details=f"Sigma Rule Match: '{rule.get('title')}' - {rule.get('description')} (MITRE: {mitre_str})",
                    ioc_detected=rule.get("title")
                )
                matches.append(match_artifact)
                
        except Exception as e:
            print(f"Error evaluating Sigma rule {rule.get('title', 'Unknown')}: {e}")
            
    return matches

def scan_artifacts_with_sigma(artifacts: list):
    """Takes a list of artifacts, loads rules, and returns Sigma match artifacts."""
    rules = load_sigma_rules()
    if not rules:
        return []
        
    new_artifacts = []
    for art in artifacts:
        matches = evaluate_artifact_against_sigma(art, rules)
        new_artifacts.extend(matches)
        
    return new_artifacts
