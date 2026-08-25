with open("src/app.py", "r") as f:
    content = f.read()

# Add import for case_manager and ForensicArtifact
import_str = """
from src.agent.graph import build_forensic_graph
from src.reporting.stix_exporter import generate_stix_bundle
from src.db.case_manager import create_case, update_case, get_all_cases, get_case
from src.schema import ForensicArtifact
"""
content = content.replace("from src.agent.graph import build_forensic_graph\nfrom src.reporting.stix_exporter import generate_stix_bundle", import_str)

# Replace the layout logic
content = content.replace("# ──────────────────────────────────────────────\n# Hero Banner\n# ──────────────────────────────────────────────", """
# ──────────────────────────────────────────────
# Main Application Flow
# ──────────────────────────────────────────────
if app_mode == "📂 Case History":
    st.markdown("## 📂 Case History")
    cases = get_all_cases()
    if not cases:
        st.info("No past investigations found.")
    else:
        for c in cases:
            with st.expander(f"Case {c['id'][:8]} — {c['timestamp']} — {c['status']}"):
                st.write(f"**Model:** {c['llm_model']}")
                if st.button(f"Load Case {c['id'][:8]}", key=c['id']):
                    st.session_state.loaded_case = c['id']
                    
        if 'loaded_case' in st.session_state:
            st.markdown("---")
            loaded = get_case(st.session_state.loaded_case)
            st.markdown(f"### 📋 Case: {loaded['id']}")
            
            # Reconstruct final state for rendering
            artifacts = [ForensicArtifact(**a) for a in loaded['artifacts']]
            final_state = {
                "artifacts": artifacts,
                "timeline": loaded['timeline'],
                "endpoint_summary": loaded['endpoint_summary'],
                "network_summary": loaded['network_summary'],
                "memory_summary": loaded['memory_summary'],
                "report": loaded['report']
            }
            start_time = time.time()
            elapsed = 0 # Precomputed
            # The rest of the rendering logic will just pick up `final_state`
            # We'll skip the "Upload Section" by wrapping the rest in an else block below!
""")

# We need to wrap the Hero Banner and Upload section in `if app_mode == "🆕 New Investigation":`
content = content.replace('st.markdown("""\n<div class="hero-banner">', 'if app_mode == "🆕 New Investigation":\n    st.markdown("""\n    <div class="hero-banner">')

# But it's easier to just do it via regex or writing a cleaner patch script
