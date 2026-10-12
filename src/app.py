import json
import os
import sys
import time
from datetime import datetime

# Ensure project root is in sys.path before importing from src
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import streamlit as st

from src.agent.graph import build_forensic_graph
from src.db.case_manager import create_case, get_all_cases, get_case, update_case
from src.enrichment.threat_intel import enrich_iocs
from src.reporting.graph_viz import render_attack_graph
from src.reporting.stix_exporter import generate_stix_bundle
from src.reporting.timeline_viz import render_timeline_chart
from src.schema import ForensicArtifact


# ──────────────────────────────────────────────
# Page Config
# ──────────────────────────────────────────────
st.set_page_config(
    page_title="SENTINEL — Autonomous Forensic Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ──────────────────────────────────────────────
# Custom CSS
# ──────────────────────────────────────────────
st.markdown("""
<style>
/* ── Global ── */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&display=swap');

:root {
    --bg-primary: #0a0e17;
    --bg-secondary: #111827;
    --bg-card: #1a1f2e;
    --bg-card-hover: #242b3d;
    --accent-cyan: #06d6a0;
    --accent-blue: #118ab2;
    --accent-red: #ef476f;
    --accent-amber: #ffd166;
    --accent-purple: #8338ec;
    --text-primary: #e8eaed;
    --text-secondary: #9ca3af;
    --border-color: #2d3748;
}

.stApp {
    background-color: var(--bg-primary) !important;
    font-family: 'Inter', sans-serif !important;
}

/* ── Sidebar ── */
section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0d1117 0%, #111827 100%) !important;
    border-right: 1px solid var(--border-color) !important;
}

section[data-testid="stSidebar"] .stMarkdown p {
    color: var(--text-secondary) !important;
    font-size: 0.85rem;
}

/* ── Headers ── */
h1, h2, h3 {
    font-family: 'Inter', sans-serif !important;
    font-weight: 700 !important;
}

/* ── Hero Banner ── */
.hero-banner {
    background: linear-gradient(135deg, #0d1b2a 0%, #1b2838 50%, #0d1b2a 100%);
    border: 1px solid #1e3a5f;
    border-radius: 16px;
    padding: 2.5rem 3rem;
    margin-bottom: 2rem;
    position: relative;
    overflow: hidden;
}

.hero-banner::before {
    content: '';
    position: absolute;
    top: 0; left: 0;
    width: 100%; height: 3px;
    background: linear-gradient(90deg, var(--accent-cyan), var(--accent-blue), var(--accent-purple));
}

.hero-title {
    font-size: 2.4rem;
    font-weight: 800;
    background: linear-gradient(135deg, #06d6a0, #118ab2);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    margin: 0 0 0.3rem 0;
    letter-spacing: -0.02em;
}

.hero-subtitle {
    color: #9ca3af;
    font-size: 1rem;
    font-weight: 400;
    margin: 0;
}

/* ── Stat Cards ── */
.stat-row {
    display: flex;
    gap: 1rem;
    margin: 1.5rem 0;
}

.stat-card {
    flex: 1;
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 1.2rem 1.5rem;
    text-align: center;
    transition: all 0.2s ease;
}

.stat-card:hover {
    border-color: var(--accent-cyan);
    transform: translateY(-2px);
    box-shadow: 0 4px 20px rgba(6, 214, 160, 0.1);
}

.stat-value {
    font-size: 2rem;
    font-weight: 800;
    font-family: 'JetBrains Mono', monospace;
    margin: 0;
}

.stat-label {
    font-size: 0.75rem;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin: 0.3rem 0 0 0;
}

.cyan { color: var(--accent-cyan); }
.red { color: var(--accent-red); }
.amber { color: var(--accent-amber); }
.purple { color: var(--accent-purple); }
.blue { color: var(--accent-blue); }

/* ── Section Cards ── */
.section-card {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 1.5rem;
    margin-bottom: 1rem;
}

.section-header {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    margin-bottom: 1rem;
    padding-bottom: 0.8rem;
    border-bottom: 1px solid var(--border-color);
}

.section-icon {
    font-size: 1.3rem;
}

.section-title {
    font-size: 1.1rem;
    font-weight: 700;
    color: var(--text-primary);
    margin: 0;
}

/* ── Timeline ── */
.timeline-event {
    display: flex;
    gap: 1rem;
    padding: 0.8rem 0;
    border-bottom: 1px solid rgba(45, 55, 72, 0.5);
}

.timeline-event:last-child {
    border-bottom: none;
}

.timeline-dot {
    width: 10px;
    height: 10px;
    border-radius: 50%;
    margin-top: 6px;
    flex-shrink: 0;
}

.timeline-content {
    flex: 1;
}

.timeline-time {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    color: var(--accent-cyan);
}

.timeline-desc {
    font-size: 0.85rem;
    color: var(--text-primary);
    margin-top: 0.2rem;
}

.timeline-source {
    font-size: 0.7rem;
    color: var(--text-secondary);
    margin-top: 0.15rem;
}

/* ── IOC Tag ── */
.ioc-tag {
    display: inline-block;
    background: rgba(239, 71, 111, 0.15);
    border: 1px solid rgba(239, 71, 111, 0.3);
    color: var(--accent-red);
    padding: 0.3rem 0.8rem;
    border-radius: 20px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.8rem;
    margin: 0.25rem 0.3rem;
    font-weight: 500;
}

/* ── TTP Badge ── */
.ttp-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    background: rgba(131, 56, 236, 0.15);
    border: 1px solid rgba(131, 56, 236, 0.3);
    color: var(--accent-purple);
    padding: 0.35rem 0.9rem;
    border-radius: 8px;
    font-size: 0.8rem;
    margin: 0.25rem 0.3rem;
    font-weight: 600;
}

/* ── Status Badges ── */
.status-badge {
    display: inline-block;
    padding: 0.25rem 0.75rem;
    border-radius: 20px;
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.status-critical {
    background: rgba(239, 71, 111, 0.2);
    border: 1px solid rgba(239, 71, 111, 0.4);
    color: var(--accent-red);
}

.status-active {
    background: rgba(6, 214, 160, 0.2);
    border: 1px solid rgba(6, 214, 160, 0.4);
    color: var(--accent-cyan);
}

/* ── Pipeline Steps ── */
.pipeline-steps {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    margin: 1rem 0;
    flex-wrap: wrap;
}

.pipeline-step {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 0.5rem 0.85rem;
    font-size: 0.75rem;
    color: var(--text-secondary);
}

.pipeline-step.done {
    border-color: var(--accent-cyan);
    color: var(--accent-cyan);
    background: rgba(6, 214, 160, 0.08);
}

.pipeline-arrow {
    color: var(--border-color);
    font-size: 0.9rem;
}

/* ── Agent Output Card ── */
.agent-card {
    background: linear-gradient(135deg, var(--bg-card) 0%, #1e2536 100%);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 1.2rem 1.5rem;
    margin-bottom: 0.8rem;
    border-left: 3px solid var(--accent-cyan);
}

.agent-card.email { border-left-color: var(--accent-amber); }
.agent-card.remediation { border-left-color: var(--accent-red); }
.agent-card.hunter { border-left-color: var(--accent-purple); }
.agent-card.ticket { border-left-color: var(--accent-blue); }

.agent-card-title {
    font-size: 0.85rem;
    font-weight: 700;
    color: var(--text-primary);
    margin: 0 0 0.6rem 0;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

/* ── File uploader ── */
[data-testid="stFileUploader"] {
    border: 2px dashed var(--border-color) !important;
    border-radius: 12px !important;
    padding: 1rem !important;
}

[data-testid="stFileUploader"]:hover {
    border-color: var(--accent-cyan) !important;
}

/* ── Buttons ── */
.stButton > button {
    background: linear-gradient(135deg, var(--accent-cyan), var(--accent-blue)) !important;
    color: #000 !important;
    font-weight: 700 !important;
    border: none !important;
    border-radius: 10px !important;
    padding: 0.7rem 2rem !important;
    font-size: 0.95rem !important;
    transition: all 0.25s ease !important;
    text-transform: uppercase;
    letter-spacing: 0.04em;
}

.stButton > button:hover {
    transform: translateY(-1px) !important;
    box-shadow: 0 6px 25px rgba(6, 214, 160, 0.3) !important;
}

/* ── Download Button ── */
.stDownloadButton > button {
    background: transparent !important;
    color: var(--accent-cyan) !important;
    border: 1px solid var(--accent-cyan) !important;
    font-weight: 600 !important;
    border-radius: 8px !important;
}

.stDownloadButton > button:hover {
    background: rgba(6, 214, 160, 0.1) !important;
}

/* ── Expander ── */
.streamlit-expanderHeader {
    background: var(--bg-card) !important;
    border: 1px solid var(--border-color) !important;
    border-radius: 8px !important;
}

/* ── JSON viewer ── */
[data-testid="stJson"] {
    background: #0d1117 !important;
    border: 1px solid var(--border-color) !important;
    border-radius: 8px !important;
    padding: 1rem !important;
}

/* ── Tabs Navigation ── */
.stTabs [data-baseweb="tab-list"] {
    gap: 10px !important;
    background: #111827 !important;
    border-radius: 14px !important;
    padding: 8px 12px !important;
    border: 1px solid #1f2937 !important;
    display: flex !important;
    flex-wrap: wrap !important;
    align-items: center !important;
    margin-bottom: 1.5rem !important;
}

.stTabs [data-baseweb="tab"] {
    border-radius: 10px !important;
    color: #94a3b8 !important;
    font-weight: 600 !important;
    font-size: 0.85rem !important;
    padding: 8px 16px !important;
    margin: 2px 0 !important;
    background: #1a2234 !important;
    border: 1px solid #2d3748 !important;
    transition: all 0.2s ease-in-out !important;
    white-space: nowrap !important;
}

.stTabs [data-baseweb="tab"]:hover {
    color: #f8fafc !important;
    background: #242f45 !important;
    border-color: #3b82f6 !important;
    transform: translateY(-1px) !important;
}

.stTabs [aria-selected="true"] {
    background: linear-gradient(135deg, rgba(6, 214, 160, 0.2), rgba(17, 138, 178, 0.2)) !important;
    color: var(--accent-cyan) !important;
    border: 1px solid var(--accent-cyan) !important;
    box-shadow: 0 0 15px rgba(6, 214, 160, 0.25) !important;
}

.stTabs [data-baseweb="tab-highlight"],
.stTabs [data-baseweb="tab-border"] {
    display: none !important;
}

/* ── Spinner ── */
.stSpinner > div {
    border-top-color: var(--accent-cyan) !important;
}

/* ── Threat Intel Score ── */
.ti-score {
    display: inline-flex;
    align-items: center;
    gap: 0.3rem;
    padding: 0.2rem 0.6rem;
    border-radius: 6px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    font-weight: 600;
}

.ti-malicious {
    background: rgba(239, 71, 111, 0.2);
    color: var(--accent-red);
}

.ti-clean {
    background: rgba(6, 214, 160, 0.2);
    color: var(--accent-cyan);
}

/* ── Footer ── */
.footer {
    text-align: center;
    color: var(--text-secondary);
    font-size: 0.7rem;
    padding: 2rem 0 1rem;
    border-top: 1px solid var(--border-color);
    margin-top: 3rem;
}
</style>
""", unsafe_allow_html=True)


# ──────────────────────────────────────────────
# Sidebar
# ──────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style="text-align:center; padding: 1.5rem 0 1rem;">
        <div style="font-size: 2.5rem;">🛡️</div>
        <div style="font-size: 1.4rem; font-weight: 800; 
                    background: linear-gradient(135deg, #06d6a0, #118ab2);
                    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
                    letter-spacing: -0.02em;">SENTINEL</div>
        <div style="font-size: 0.7rem; color: #9ca3af; letter-spacing: 0.15em; text-transform: uppercase; margin-top: 2px;">
            Autonomous Forensic Agent
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")

    st.markdown("##### 🔍 Navigation")
    app_mode = st.radio(
        "Mode", ["🆕 New Investigation", "📂 Case History"], label_visibility="collapsed")

    st.markdown("---")

    st.markdown("##### ⚙️ Engine Configuration")
    llm_model = st.selectbox(
        "LLM Model", ["llama3.1", "mistral", "llama3.1:70b"], index=0)
    embedding_model = st.selectbox(
        "Embedding Model", ["all-MiniLM-L6-v2"], index=0)
    top_k = st.slider("RAG Top-K Results", 1, 10, 3)

    st.markdown("---")

    st.markdown("##### 🌍 Threat Intel APIs (Optional)")
    vt_api_key = st.text_input("VirusTotal API Key", type="password")
    abuse_api_key = st.text_input("AbuseIPDB API Key", type="password")

    st.markdown("---")

    st.markdown("##### 📁 Supported Formats")
    st.markdown("""
    <div style="font-size: 0.8rem; color: #9ca3af; line-height: 1.8;">
        <code style="background:#1e293b; padding:2px 6px; border-radius:4px; color:#06d6a0;">.evtx</code> Windows Event Logs<br>
        <code style="background:#1e293b; padding:2px 6px; border-radius:4px; color:#118ab2;">.pcap</code> <code style="background:#1e293b; padding:2px 6px; border-radius:4px; color:#118ab2;">.cap</code> Network Captures<br>
        <code style="background:#1e293b; padding:2px 6px; border-radius:4px; color:#8338ec;">.raw</code> <code style="background:#1e293b; padding:2px 6px; border-radius:4px; color:#8338ec;">.mem</code> <code style="background:#1e293b; padding:2px 6px; border-radius:4px; color:#8338ec;">.vmem</code> Memory Dumps<br>
        <code style="background:#1e293b; padding:2px 6px; border-radius:4px; color:#ffd166;">.eml</code> Email / Phishing
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")

    st.markdown("##### 🔗 Quick Links")
    st.markdown("""
    <div style="font-size: 0.8rem; line-height: 2;">
        <a href="https://attack.mitre.org" target="_blank" style="color: #06d6a0; text-decoration: none;">↗ MITRE ATT&CK</a><br>
        <a href="https://oasis-open.github.io/cti-documentation/stix/intro" target="_blank" style="color: #06d6a0; text-decoration: none;">↗ STIX 2.1 Specification</a><br>
        <a href="https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES" target="_blank" style="color: #06d6a0; text-decoration: none;">↗ EVTX Attack Samples</a>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")

    st.markdown(f"""
    <div style="font-size: 0.7rem; color: #4a5568; text-align: center;">
        Engine: Ollama ({llm_model})<br>
        KB: ChromaDB + {embedding_model}<br>
        v2.0.0 • Local Mode 🔒
    </div>
    """, unsafe_allow_html=True)


# ──────────────────────────────────────────────
# Helper: Extract MITRE TTPs from artifact details
# ──────────────────────────────────────────────
def extract_ttps(artifacts):
    """Extract MITRE TTP IDs from Sigma match details and YARA metadata."""
    import re
    ttps = set()
    for a in artifacts:
        if "MITRE:" in a.details:
            # Extract technique IDs like T1059, T1059.001 etc.
            found = re.findall(r'T\d{4}(?:\.\d{3})?', a.details)
            ttps.update(found)
        # Also extract from SIGMA/YARA tags in details
        if a.source_type in ("SIGMA_MATCH", "YARA_MATCH"):
            found = re.findall(r'T\d{4}(?:\.\d{3})?', a.details)
            ttps.update(found)
    return ttps


# ──────────────────────────────────────────────
# Main Application Flow
# ──────────────────────────────────────────────
if app_mode == "🆕 New Investigation":
    st.markdown('''
    <div class="hero-banner">
        <p class="hero-title">SENTINEL</p>
        <p class="hero-subtitle">
            AI-Powered Autonomous Forensic Analysis • Upload forensic artifacts to automatically 
            parse, enrich via MITRE ATT&CK, correlate with LLM reasoning, and generate STIX 2.1 IOC reports.
        </p>
    </div>
    ''', unsafe_allow_html=True)

    st.markdown('''
    <div class="pipeline-steps">
        <div class="pipeline-step">📥 Upload</div>
        <div class="pipeline-arrow">→</div>
        <div class="pipeline-step">🔍 Parse</div>
        <div class="pipeline-arrow">→</div>
        <div class="pipeline-step">🧠 Enrich</div>
        <div class="pipeline-arrow">→</div>
        <div class="pipeline-step">⚡ Correlate</div>
        <div class="pipeline-arrow">→</div>
        <div class="pipeline-step">🛡️ Remediate</div>
        <div class="pipeline-arrow">→</div>
        <div class="pipeline-step">🔍 Hunt</div>
        <div class="pipeline-arrow">→</div>
        <div class="pipeline-step">🎫 Ticket</div>
        <div class="pipeline-arrow">→</div>
        <div class="pipeline-step">📄 Report</div>
    </div>
    ''', unsafe_allow_html=True)

    st.markdown('''
    <div class="section-card">
        <div class="section-header">
            <span class="section-icon">📤</span>
            <p class="section-title">Upload Forensic Artifacts</p>
        </div>
    </div>
    ''', unsafe_allow_html=True)

    uploaded_files = st.file_uploader(
        "Drag and drop files here",
        accept_multiple_files=True,
        type=["evtx", "pcap", "cap", "raw", "mem", "vmem", "eml"],
        label_visibility="collapsed"
    )

    col_btn1, col_btn2, col_btn3 = st.columns([1, 1, 4])
    with col_btn1:
        run_btn = st.button("🚀 Run Analysis", use_container_width=True)
    with col_btn2:
        if st.button("🗑️ Clear", use_container_width=True):
            st.rerun()

    if run_btn and uploaded_files:
        start_time = time.time()

        # ── CREATE DB CASE ──
        case_id = create_case(llm_model)

        os.makedirs("temp_uploads", exist_ok=True)
        file_paths = []
        for f in uploaded_files:
            fp = os.path.join("temp_uploads", f.name)
            with open(fp, "wb") as out:
                out.write(f.read())
            file_paths.append(fp)

        progress = st.progress(0, text="Initializing agent pipeline...")
        status_box = st.empty()

        try:
            app = build_forensic_graph()
            state_input = {
                "file_paths": file_paths,
                "llm_model": llm_model,
                "artifacts": [],
                "endpoint_summary": "",
                "network_summary": "",
                "memory_summary": "",
                "email_summary": "",
                "timeline": "",
                "report": "",
                "remediation_plan": "",
                "threat_hunt_queries": "",
                "jira_ticket": "",
            }

            final_state = state_input

            for output in app.stream(state_input):
                for node_name, state_update in output.items():
                    if node_name == "parser":
                        progress.progress(
                            10, text="📥 Artifact parsing complete.")
                        status_box.info(
                            "🔍 Extracted artifacts and ran YARA/Sigma deterministic checks.")
                    elif node_name == "endpoint_agent":
                        progress.progress(
                            25, text="💻 Endpoint Analyst complete.")
                        status_box.info(
                            "💻 **Endpoint Agent** summarized EVTX and Sigma matches.")
                    elif node_name == "network_agent":
                        progress.progress(
                            35, text="🌐 Network Analyst complete.")
                        status_box.info(
                            "🌐 **Network Agent** summarized PCAP and HTTP traffic.")
                    elif node_name == "memory_agent":
                        progress.progress(
                            45, text="🧠 Memory Analyst complete.")
                        status_box.info(
                            "🧠 **Memory Agent** summarized process injections and YARA matches.")
                    elif node_name == "email_agent":
                        progress.progress(
                            55, text="📧 Email Analyst complete.")
                        status_box.info(
                            "📧 **Email Agent** analyzed phishing indicators and header anomalies.")
                    elif node_name == "correlation":
                        progress.progress(
                            65, text="⚡ Lead SOC Analyst correlated findings.")
                        status_box.info(
                            "⚡ **Lead Agent** fused multi-domain intelligence into a chronological narrative.")
                    elif node_name == "reporter":
                        progress.progress(70, text="📄 Report generated.")
                        status_box.info(
                            "📄 Compiled Markdown report with IOC extraction.")
                    elif node_name == "remediation_agent":
                        progress.progress(
                            80, text="🛡️ SOAR Remediation plan generated.")
                        status_box.info(
                            "🛡️ **SOAR Agent** generated firewall rules, EDR commands, and detection signatures.")
                    elif node_name == "threat_hunter_agent":
                        progress.progress(
                            88, text="🔍 Threat hunting queries generated.")
                        status_box.info(
                            "🔍 **Threat Hunter** generated Splunk SPL, KQL, and EQL queries.")
                    elif node_name == "ticketing_agent":
                        progress.progress(
                            95, text="🎫 SOC ticket generated.")
                        status_box.info(
                            "🎫 **Ticketing Engine** generated Jira/ServiceNow API payload.")

                    final_state.update(state_update)

            # ── EXTERNAL THREAT INTEL ──
            if vt_api_key or abuse_api_key:
                progress.progress(98, text="🌍 Querying External Threat Intel APIs...")
                status_box.info("🌍 Querying VirusTotal and AbuseIPDB...")
                iocs_to_check = [a.ioc_detected for a in final_state.get("artifacts", []) if a.ioc_detected]
                final_state["threat_intel"] = enrich_iocs(iocs_to_check, vt_api_key, abuse_api_key)
            else:
                final_state["threat_intel"] = {}

            # ── UPDATE DB CASE ──
            update_case(case_id, final_state)

            elapsed = round(time.time() - start_time, 1)
            progress.progress(
                100, text=f"✅ Analysis complete! (Case ID: {case_id[:8]})")
            status_box.empty()

            st.session_state.final_state = final_state
            st.session_state.elapsed = elapsed

        except Exception as e:
            progress.empty()
            status_box.empty()
            st.error(f"❌ **Pipeline Error:** {e}")
            import traceback
            st.code(traceback.format_exc())

elif app_mode == "📂 Case History":
    st.markdown('''
    <div class="hero-banner">
        <p class="hero-title">Case Management</p>
        <p class="hero-subtitle">Review previous autonomous forensic investigations.</p>
    </div>
    ''', unsafe_allow_html=True)

    cases = get_all_cases()
    if not cases:
        st.info("No past investigations found.")
    else:
        for c in cases:
            with st.container():
                col1, col2, col3 = st.columns([3, 1, 1])
                # Format time string gracefully
                dt = c['timestamp'][:16].replace('T', ' ')
                status_clr = "green" if c['status'] == "COMPLETED" else "orange"
                col1.markdown(
                    f"**Case:** `{c['id'][:8]}` &nbsp;|&nbsp; **Time:** {dt} &nbsp;|&nbsp; **Status:** <span style='color:{status_clr};'>{c['status']}</span>", unsafe_allow_html=True)
                col2.write(f"🤖 {c['llm_model']}")
                if col3.button("📂 View Report", key=c['id']):
                    st.session_state.loaded_case = c['id']

        if 'loaded_case' in st.session_state:
            st.markdown("---")
            loaded = get_case(st.session_state.loaded_case)
            st.markdown(f"### 📋 Active Case: `{loaded['id']}`")

            artifacts = [ForensicArtifact(**a) for a in loaded['artifacts']]
            st.session_state.final_state = {
                "artifacts": artifacts,
                "timeline": loaded['timeline'],
                "endpoint_summary": loaded['endpoint_summary'],
                "network_summary": loaded['network_summary'],
                "memory_summary": loaded['memory_summary'],
                "email_summary": loaded.get('email_summary', ''),
                "report": loaded['report'],
                "remediation_plan": loaded.get('remediation_plan', ''),
                "threat_hunt_queries": loaded.get('threat_hunt_queries', ''),
                "jira_ticket": loaded.get('jira_ticket', ''),
                "threat_intel": loaded.get('threat_intel', {})
            }
            st.session_state.elapsed = "Archived"


# ──────────────────────────────────────────────
# Results Dashboard
# ──────────────────────────────────────────────
if 'final_state' in st.session_state:
    final_state = st.session_state.final_state
    elapsed = st.session_state.elapsed
    artifacts = final_state.get("artifacts", [])
    iocs = [a for a in artifacts if a.ioc_detected]
    ttps = extract_ttps(artifacts)
    threat_intel = final_state.get("threat_intel", {})

    # ── Stat Cards ──
    st.markdown(f"""
    <div class="stat-row">
        <div class="stat-card">
            <p class="stat-value cyan">{len(artifacts)}</p>
            <p class="stat-label">Artifacts Parsed</p>
        </div>
        <div class="stat-card">
            <p class="stat-value red">{len(set(a.ioc_detected for a in iocs))}</p>
            <p class="stat-label">Unique IOCs</p>
        </div>
        <div class="stat-card">
            <p class="stat-value purple">{len(ttps) if ttps else "—"}</p>
            <p class="stat-label">MITRE TTPs</p>
        </div>
        <div class="stat-card">
            <p class="stat-value blue">{len(set(a.source_type for a in artifacts))}</p>
            <p class="stat-label">Source Types</p>
        </div>
        <div class="stat-card">
            <p class="stat-value amber">{elapsed}s</p>
            <p class="stat-label">Analysis Time</p>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # ── Results Tabs ──
    tab_timeline, tab_graph, tab_agents, tab_iocs, tab_intel, tab_remediation, tab_hunting, tab_ticket, tab_report = st.tabs([
        "📊 Timeline",
        "🔗 Attack Graph",
        "🤖 Agent Summaries",
        "🎯 IOCs & Evidence",
        "🌍 Threat Intel",
        "🛡️ SOAR Remediation",
        "🔍 Threat Hunting",
        "🎫 SOC Ticket",
        "📋 Report & STIX",
    ])

    # ── Tab 1: Interactive Timeline ──
    with tab_timeline:
        st.markdown("""
        <div class="section-card">
            <div class="section-header">
                <span class="section-icon">📊</span>
                <p class="section-title">Attack Timeline & Narrative</p>
                <span class="status-badge status-critical">INCIDENT</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Interactive Plotly chart
        fig = render_timeline_chart(artifacts)
        if fig:
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.caption("No timestamped artifacts available for chart rendering.")

        st.markdown("---")
        st.markdown("#### 📝 AI-Generated Narrative")
        st.markdown(final_state.get("timeline", "No timeline generated."))

    # ── Tab 2: Attack Graph ──
    with tab_graph:
        st.markdown("""
        <div class="section-card">
            <div class="section-header">
                <span class="section-icon">🔗</span>
                <p class="section-title">Attack Relationship Graph</p>
                <span class="status-badge status-active">INTERACTIVE</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.caption("Nodes: 🔵 Hosts  •  💎 Users  •  ⭐ IOCs  •  🟡 Global Scans")

        if artifacts:
            rendered = render_attack_graph(artifacts)
            if not rendered:
                st.info("No relationship data available to build the attack graph.")
        else:
            st.info("No artifacts available. Run an investigation first.")

    # ── Tab 3: Agent Summaries ──
    with tab_agents:
        st.markdown("""
        <div class="section-card">
            <div class="section-header">
                <span class="section-icon">🤖</span>
                <p class="section-title">Multi-Agent Intelligence Summaries</p>
            </div>
        </div>
        """, unsafe_allow_html=True)

        col_a1, col_a2 = st.columns(2)

        with col_a1:
            st.markdown('<div class="agent-card"><p class="agent-card-title">💻 Endpoint Analyst</p>', unsafe_allow_html=True)
            st.info(final_state.get("endpoint_summary", "No summary."))
            st.markdown('</div>', unsafe_allow_html=True)

            st.markdown('<div class="agent-card"><p class="agent-card-title">🧠 Memory Analyst</p>', unsafe_allow_html=True)
            st.info(final_state.get("memory_summary", "No summary."))
            st.markdown('</div>', unsafe_allow_html=True)

        with col_a2:
            st.markdown('<div class="agent-card"><p class="agent-card-title">🌐 Network Analyst</p>', unsafe_allow_html=True)
            st.info(final_state.get("network_summary", "No summary."))
            st.markdown('</div>', unsafe_allow_html=True)

            st.markdown('<div class="agent-card email"><p class="agent-card-title">📧 Email / Phishing Analyst</p>', unsafe_allow_html=True)
            st.info(final_state.get("email_summary", "No summary."))
            st.markdown('</div>', unsafe_allow_html=True)

    # ── Tab 4: IOCs & Evidence ──
    with tab_iocs:
        st.markdown("#### 🎯 Extracted Indicators of Compromise")
        ioc_html = ""
        seen_iocs = set()
        for a in artifacts:
            ioc = a.ioc_detected
            if ioc and ioc not in seen_iocs:
                ioc_html += f'<span class="ioc-tag">{ioc}</span>\n'
                seen_iocs.add(ioc)
        if ioc_html:
            st.markdown(ioc_html, unsafe_allow_html=True)
        else:
            st.caption("No IOCs detected.")

        # MITRE TTPs
        if ttps:
            st.markdown("#### 🎯 MITRE ATT&CK TTPs Detected")
            ttp_html = ""
            for ttp in sorted(ttps):
                ttp_html += f'<span class="ttp-badge">⚔️ {ttp}</span>\n'
            st.markdown(ttp_html, unsafe_allow_html=True)

        st.markdown("---")
        st.markdown("#### 🕐 Full Evidence Log")
        for a in artifacts:
            dot_color = "#ef476f" if a.ioc_detected else "#06d6a0"
            st.markdown(f"""
            <div class="timeline-event">
                <div class="timeline-dot" style="background: {dot_color};"></div>
                <div class="timeline-content">
                    <div class="timeline-time">{a.timestamp}</div>
                    <div class="timeline-desc">{a.details}</div>
                    <div class="timeline-source">{a.source_type} • {a.host or "—"} • {a.user or "—"}</div>
                </div>
            </div>
            """, unsafe_allow_html=True)

    # ── Tab 5: External Threat Intelligence ──
    with tab_intel:
        st.markdown("""
        <div class="section-card">
            <div class="section-header">
                <span class="section-icon">🌍</span>
                <p class="section-title">External Threat Intelligence Enrichment</p>
            </div>
        </div>
        """, unsafe_allow_html=True)

        if threat_intel:
            for ioc_val, results in threat_intel.items():
                with st.expander(f"🔍 **{ioc_val}**", expanded=True):
                    ti_col1, ti_col2 = st.columns(2)

                    # VirusTotal
                    with ti_col1:
                        st.markdown("**VirusTotal**")
                        vt = results.get("virustotal")
                        if vt and "error" not in vt:
                            mal = vt.get("malicious", 0)
                            css_class = "ti-malicious" if mal > 0 else "ti-clean"
                            label = f"🚨 {mal} detections" if mal > 0 else "✅ Clean"
                            st.markdown(f'<span class="ti-score {css_class}">{label}</span>', unsafe_allow_html=True)
                            st.caption(f"Suspicious: {vt.get('suspicious', 0)} • Harmless: {vt.get('harmless', 0)}")
                            st.markdown(f"[View on VT ↗]({vt.get('link', '')})")
                        elif vt:
                            st.caption(f"⚠️ {vt.get('error', 'Unknown error')}")
                        else:
                            st.caption("Not queried")

                    # AbuseIPDB
                    with ti_col2:
                        st.markdown("**AbuseIPDB**")
                        abuse = results.get("abuseipdb")
                        if abuse and "error" not in abuse:
                            score = abuse.get("confidence_score", 0)
                            css_class = "ti-malicious" if score > 50 else "ti-clean"
                            st.markdown(f'<span class="ti-score {css_class}">Confidence: {score}%</span>', unsafe_allow_html=True)
                            st.caption(f"Total Reports: {abuse.get('total_reports', 0)}")
                            st.markdown(f"[View on AbuseIPDB ↗]({abuse.get('link', '')})")
                        elif abuse:
                            st.caption(f"⚠️ {abuse.get('error', 'Unknown error')}")
                        else:
                            st.caption("Not queried (IPs only)")
        else:
            st.info("💡 No external threat intelligence was queried. Add VirusTotal or AbuseIPDB API keys in the sidebar to enable automatic IOC enrichment.")

    # ── Tab 6: SOAR Remediation ──
    with tab_remediation:
        st.markdown("""
        <div class="section-card">
            <div class="section-header">
                <span class="section-icon">🛡️</span>
                <p class="section-title">SOAR Automated Remediation Plan</p>
                <span class="status-badge status-critical">ACTION REQUIRED</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

        remediation_text = final_state.get("remediation_plan", "")
        if remediation_text:
            st.markdown(remediation_text)
            st.download_button(
                "⬇️ Download Remediation Plan",
                data=remediation_text,
                file_name=f"sentinel_remediation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                mime="text/markdown"
            )
        else:
            st.info("No remediation plan was generated.")

    # ── Tab 7: Threat Hunting Queries ──
    with tab_hunting:
        st.markdown("""
        <div class="section-card">
            <div class="section-header">
                <span class="section-icon">🔍</span>
                <p class="section-title">SIEM Threat Hunting Queries</p>
                <span class="status-badge status-active">READY TO DEPLOY</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

        hunt_text = final_state.get("threat_hunt_queries", "")
        if hunt_text:
            st.markdown(hunt_text)
            st.download_button(
                "⬇️ Download Hunting Queries",
                data=hunt_text,
                file_name=f"sentinel_hunt_queries_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                mime="text/markdown"
            )
        else:
            st.info("No threat hunting queries were generated.")

    # ── Tab 8: SOC Ticket ──
    with tab_ticket:
        st.markdown("""
        <div class="section-card">
            <div class="section-header">
                <span class="section-icon">🎫</span>
                <p class="section-title">Automated SOC Ticket (Jira / ServiceNow)</p>
            </div>
        </div>
        """, unsafe_allow_html=True)

        ticket_text = final_state.get("jira_ticket", "")
        if ticket_text:
            # Try to parse as JSON for pretty display
            try:
                ticket_json = json.loads(ticket_text)
                st.json(ticket_json)
            except (json.JSONDecodeError, TypeError):
                # If not valid JSON, show as markdown
                st.markdown(ticket_text)

            st.download_button(
                "⬇️ Download Ticket Payload",
                data=ticket_text,
                file_name=f"sentinel_ticket_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )
        else:
            st.info("No SOC ticket was generated.")

    # ── Tab 9: Full Report & STIX ──
    with tab_report:
        st.markdown("""
        <div class="section-card">
            <div class="section-header">
                <span class="section-icon">📋</span>
                <p class="section-title">Full Forensic Report</p>
                <span class="status-badge status-active">GENERATED</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

        report_text = final_state.get("report", "No report generated.")
        st.markdown(report_text)

        st.download_button(
            "⬇️ Download Report (Markdown)",
            data=report_text,
            file_name=f"sentinel_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
            mime="text/markdown"
        )

        st.markdown("---")

        st.markdown("""
        <div class="section-card">
            <div class="section-header">
                <span class="section-icon">🔐</span>
                <p class="section-title">STIX 2.1 Threat Intelligence Bundle</p>
            </div>
        </div>
        """, unsafe_allow_html=True)

        stix_data = generate_stix_bundle(artifacts, report_text)
        st.json(json.loads(stix_data))

        st.download_button(
            "⬇️ Download STIX 2.1 JSON",
            data=stix_data,
            file_name=f"sentinel_stix_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json"
        )

# ──────────────────────────────────────────────
# Footer
# ──────────────────────────────────────────────
st.markdown(f"""
<div class="footer">
    SENTINEL v2.0.0 • Autonomous Multi-Agent Forensic System • Powered by LangGraph + Ollama + ChromaDB<br>
    7-Agent Pipeline: Parser → Endpoint → Network → Memory → Email → Correlation → SOAR → Threat Hunter → Ticketing<br>
    All data processed locally — zero data leakage • {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
</div>
""", unsafe_allow_html=True)
