import os
import shutil

from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from src.agent.graph import build_forensic_graph
from src.db.case_manager import create_case, get_all_cases, get_case, update_case
from src.enrichment.threat_intel import enrich_iocs

app = FastAPI(
    title="SENTINEL API",
    description="Autonomous Forensic Agent Backend",
    version="1.0.0"
)

# CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def run_analysis_task(case_id: str, file_paths: list[str], llm_model: str, vt_key: str, abuse_key: str):
    """Background task to run the LangGraph pipeline."""
    try:
        graph = build_forensic_graph()
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
            "remediation_plan": ""
        }
        
        final_state = state_input
        # We don't stream here because it's running headlessly
        for output in graph.stream(state_input):
            for _, state_update in output.items():
                final_state.update(state_update)
                
        # Threat Intel Enrichment
        if vt_key or abuse_key:
            iocs = [a.ioc_detected for a in final_state.get("artifacts", []) if a.ioc_detected]
            final_state["threat_intel"] = enrich_iocs(iocs, vt_key, abuse_key)
        else:
            final_state["threat_intel"] = {}
            
        update_case(case_id, final_state)
        
    except Exception as e:
        print(f"Error in background task for case {case_id}: {e}")
        # In a real app we'd update the case status to 'FAILED'
    finally:
        # Cleanup temp files
        for fp in file_paths:
            try:
                os.remove(fp)
            except:
                pass

@app.post("/api/v1/analyze")
async def analyze_artifacts(
    background_tasks: BackgroundTasks,
    files: list[UploadFile] = File(...),
    llm_model: str = Form("llama3.1"),
    vt_key: str | None = Form(""),
    abuse_key: str | None = Form("")
):
    """Uploads forensic artifacts and starts analysis asynchronously."""
    case_id = create_case(llm_model)
    
    os.makedirs("temp_api_uploads", exist_ok=True)
    file_paths = []
    
    for file in files:
        fp = os.path.join("temp_api_uploads", f"{case_id}_{file.filename}")
        with open(fp, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        file_paths.append(fp)
        
    # Kick off background task
    background_tasks.add_task(run_analysis_task, case_id, file_paths, llm_model, vt_key, abuse_key)
    
    return {"status": "Analysis Started", "case_id": case_id}

@app.get("/api/v1/cases")
def list_cases():
    """Returns all forensic cases from the database."""
    return get_all_cases()

@app.get("/api/v1/cases/{case_id}")
def get_case_details(case_id: str):
    """Returns the full forensic state for a specific case."""
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case

@app.get("/health")
def health_check():
    return {"status": "ok"}
