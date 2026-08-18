import uuid
import logging
import importlib.util
import sys
import os
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

# Add project root to sys.path to import rag_assistant from parent directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from rag_assistant.chains.rag_chain import get_rag_pipeline, RAGQuery

from models.database import get_db, ChatMessageDB
from models.schemas import ChatRequest, ChatResponse, ChatSource, ChatMessageResponse

logger = logging.getLogger("vulndetect")
router = APIRouter()

# Initialize the new RAG pipeline
rag_pipeline = get_rag_pipeline("default")



@router.post("/rag/chat", response_model=ChatResponse)
async def chat(request: ChatRequest, db: Session = Depends(get_db)):
    """Chat with the RAG vulnerability assistant."""
    session_id = request.session_id or str(uuid.uuid4())

    _store_message(db, session_id, "user", request.message)

    # Use the new standalone rag_assistant module
    query_obj = RAGQuery(question=request.message, session_id=session_id)
    result = rag_pipeline.query(query_obj)
    
    # If the response indicates an error, log it
    if hasattr(result, "metadata") and result.metadata.get("error"):
        logger.error(f"RAG query returned error: {result.metadata['error']}")

    answer = result.answer
    # The new pipeline returns a list of dictionaries with 'content', 'score', and 'metadata', 
    # but the frontend expects 'cve_id' and 'score'. Let's adapt it.
    sources = []
    for s in result.sources:
        meta = s.get("metadata", {})
        sources.append(ChatSource(
            cve_id=meta.get("cve_id", meta.get("id", "Unknown")),
            content=s.get("content", ""),
            score=s.get("score", 0.0)
        ))

    _store_message(
        db, session_id, "assistant", answer, sources=[s.model_dump() for s in sources]
    )

    return ChatResponse(
        answer=answer,
        sources=sources,
        session_id=session_id,
    )


@router.get("/rag/history/{session_id}", response_model=list[ChatMessageResponse])
async def get_chat_history(session_id: str, db: Session = Depends(get_db)):
    """Get chat history for a session."""
    messages = (
        db.query(ChatMessageDB)
        .filter(ChatMessageDB.session_id == session_id)
        .order_by(ChatMessageDB.created_at.asc())
        .all()
    )
    return [ChatMessageResponse.model_validate(m) for m in messages]


@router.get("/rag/sessions")
async def list_sessions(db: Session = Depends(get_db)):
    """List all chat sessions with message counts."""
    sessions = (
        db.query(
            ChatMessageDB.session_id,
            func.count(ChatMessageDB.id).label("message_count"),
            func.max(ChatMessageDB.created_at).label("last_activity"),
        )
        .group_by(ChatMessageDB.session_id)
        .order_by(func.max(ChatMessageDB.created_at).desc())
        .all()
    )
    return [
        {
            "session_id": s.session_id,
            "message_count": s.message_count,
            "last_activity": str(s.last_activity),
        }
        for s in sessions
    ]


@router.delete("/rag/sessions/{session_id}")
async def delete_session(session_id: str, db: Session = Depends(get_db)):
    """Delete a chat session and its messages."""
    deleted = (
        db.query(ChatMessageDB).filter(ChatMessageDB.session_id == session_id).delete()
    )
    db.commit()
    return {"message": f"Deleted {deleted} messages"}


@router.post("/rag/index")
async def index_cves():
    """Trigger re-indexing of CVE data into ChromaDB."""
    scripts_dir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "scripts")
    )
    seed_path = os.path.join(scripts_dir, "seed_cve_data.py")
    if not os.path.isfile(seed_path):
        raise HTTPException(status_code=500, detail="seed_cve_data.py not found")

    spec = importlib.util.spec_from_file_location("seed_cve_data", seed_path)
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception:
        logger.exception("Failed to load seed_cve_data")
        raise HTTPException(status_code=500, detail="Failed to load indexing script")

    count = module.seed_data()
    return {"message": f"Indexed {count} CVE entries", "count": count}


def _store_message(
    db: Session, session_id: str, role: str, content: str, sources: list | None = None
):
    msg = ChatMessageDB(
        session_id=session_id,
        role=role,
        content=content,
        sources=sources or [],
    )
    db.add(msg)
    db.commit()
