import time
from src.knowledge.vector_store import VectorStore, FunctionRecord
from src.knowledge.identity import ExperienceRAG
from src.intake.binary_profiler import BinaryProfiler

vs = VectorStore({"knowledge": {"vector_store": {"persist_dir": "./data/chroma", "collection": "test_rag"}}})
rag = ExperienceRAG({}, vector_store=vs)

profile = BinaryProfiler().profile("C:/Windows/System32/calc.exe")
profile_dict = profile if isinstance(profile, dict) else vars(profile)

print("\n[+] RAG Query based on calc.exe profile (PE, C/C++)...")
episodes = rag.recall_similar_episodes(current_profile=profile_dict, limit=2)

print("\n--- AGENT RECALLED EXPERIENCES ---")
for ep in episodes:
    print(ep)
