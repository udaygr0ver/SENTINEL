import chromadb
from chromadb.utils import embedding_functions

CHROMA_DB_PATH = "data/chroma_db"

def get_mitre_mapping(query_text: str, top_k: int = 3):
    """Queries ChromaDB to find matching MITRE ATT&CK techniques."""
    try:
        client = chromadb.PersistentClient(path=CHROMA_DB_PATH)
        embed_fn = embedding_functions.SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2")
        collection = client.get_collection(name="mitre_attack", embedding_function=embed_fn)
        
        results = collection.query(
            query_texts=[query_text],
            n_results=top_k
        )
        
        matches = []
        if results and results.get("metadatas") and len(results["metadatas"]) > 0:
            for idx in range(len(results["metadatas"][0])):
                meta = results["metadatas"][0][idx]
                doc = results["documents"][0][idx]
                dist = results["distances"][0][idx]
                
                # Simple distance threshold to avoid returning irrelevant stuff
                if dist < 1.5:
                    matches.append({
                        "technique_id": meta.get("technique_id"),
                        "name": meta.get("name"),
                        "description": doc[:500] + "...", # Truncate description for LLM prompt context
                        "distance": dist
                    })
        return matches
    except Exception as e:
        print(f"Error querying ChromaDB: {e}")
        return []

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        query = sys.argv[1]
        print(f"Querying MITRE for: {query}")
        results = get_mitre_mapping(query)
        for r in results:
            print(f"- {r['technique_id']}: {r['name']} (Dist: {r['distance']})")
