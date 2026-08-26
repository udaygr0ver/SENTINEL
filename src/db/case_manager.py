import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data", "sentinel.db")

def get_db_connection():
    # Ensure data directory exists
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cases (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            llm_model TEXT NOT NULL,
            status TEXT NOT NULL,
            endpoint_summary TEXT,
            network_summary TEXT,
            memory_summary TEXT,
            email_summary TEXT,
            timeline TEXT,
            report TEXT,
            artifacts_json TEXT,
            threat_intel_json TEXT,
            remediation_plan TEXT,
            threat_hunt_queries TEXT,
            jira_ticket TEXT
        )
    ''')
    conn.commit()
    conn.close()

def create_case(llm_model: str) -> str:
    """Creates a new case and returns the UUID."""
    case_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat() + "Z"
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO cases (id, timestamp, llm_model, status)
        VALUES (?, ?, ?, ?)
    ''', (case_id, timestamp, llm_model, 'IN_PROGRESS'))
    conn.commit()
    conn.close()
    
    return case_id

def update_case(case_id: str, state: dict):
    """Updates a case with the final analysis state."""
    artifacts = state.get("artifacts", [])
    # Serialize artifacts to dicts
    artifacts_list = [a.model_dump() for a in artifacts]
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE cases 
        SET status = ?, 
            endpoint_summary = ?, 
            network_summary = ?, 
            memory_summary = ?,
            email_summary = ?, 
            timeline = ?, 
            report = ?, 
            artifacts_json = ?,
            remediation_plan = ?,
            threat_hunt_queries = ?,
            jira_ticket = ?,
            threat_intel_json = ?
        WHERE id = ?
    ''', (
        'COMPLETED',
        state.get('endpoint_summary', ''),
        state.get('network_summary', ''),
        state.get('memory_summary', ''),
        state.get('email_summary', ''),
        state.get('timeline', ''),
        state.get('report', ''),
        json.dumps(artifacts_list),
        state.get('remediation_plan', ''),
        state.get('threat_hunt_queries', ''),
        state.get('jira_ticket', ''),
        json.dumps(state.get('threat_intel', {})),
        case_id
    ))
    conn.commit()
    conn.close()

def get_all_cases():
    """Retrieves all cases, ordered by newest first."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, timestamp, status, llm_model FROM cases ORDER BY timestamp DESC')
    cases = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return cases

def get_case(case_id: str):
    """Retrieves a specific case by ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM cases WHERE id = ?', (case_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        case = dict(row)
        case['artifacts'] = json.loads(case['artifacts_json']) if case['artifacts_json'] else []
        case['threat_intel'] = json.loads(case['threat_intel_json']) if case.get('threat_intel_json') else {}
        return case
    return None

# Initialize on import
init_db()
