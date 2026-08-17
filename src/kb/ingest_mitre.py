import requests
import json
import chromadb
from chromadb.utils import embedding_functions
from sentence_transformers import SentenceTransformer

MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
CHROMA_DB_PATH = "data/chroma_db"

def ingest_mitre():
    print("Downloading MITRE ATT&CK STIX 2.1 data...")
    response = requests.get(MITRE_URL)
    response.raise_for_status()
    stix_data = response.json()
    
    print("Initializing ChromaDB...")
    # Initialize Chroma client
    client = chromadb.PersistentClient(path=CHROMA_DB_PATH)
    
    # Use sentence-transformers explicitly to avoid Chroma's ONNX download timeouts
    print("Loading SentenceTransformer model...")
    embed_fn = embedding_functions.SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2")
    
    collection = client.get_or_create_collection(
        name="mitre_attack",
        embedding_function=embed_fn,
        metadata={"hnsw:space": "cosine"}
    )
    
    print("Parsing STIX objects...")
    docs = []
    metadatas = []
    ids = []
    
    for obj in stix_data.get("objects", []):
        if obj.get("type") == "attack-pattern": # These are the Techniques
            # Extract Technique ID (e.g., T1059.001)
            ext_refs = obj.get("external_references", [])
            technique_id = None
            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id")
                    break
                    
            if not technique_id:
                continue
                
            name = obj.get("name", "")
            description = obj.get("description", "")
            
            # Create a rich document for embedding
            doc_text = f"Technique ID: {technique_id}\nName: {name}\nDescription: {description}"
            
            docs.append(doc_text)
            metadatas.append({"technique_id": technique_id, "name": name})
            ids.append(technique_id)

    print(f"Upserting {len(docs)} techniques into ChromaDB...")
    # Upsert in batches to avoid max batch size limits
    batch_size = 500
    for i in range(0, len(docs), batch_size):
        collection.upsert(
            documents=docs[i:i+batch_size],
            metadatas=metadatas[i:i+batch_size],
            ids=ids[i:i+batch_size]
        )
    print("Ingestion complete.")

if __name__ == "__main__":
    ingest_mitre()
