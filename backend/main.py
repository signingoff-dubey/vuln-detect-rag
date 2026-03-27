import logging
import time
from collections import defaultdict
import uvicorn
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config import settings
from models.database import init_db
from api.routes_scan import router as scan_router
from api.routes_rag import router as rag_router
from api.routes_cve import router as cve_router

logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.FileHandler("backend.log"), logging.StreamHandler()],
)
logger = logging.getLogger("vulndetect")


# Simple in-memory rate limiter
_rate_store: dict[str, list[float]] = defaultdict(list)
RATE_LIMITS = {
    "/api/scans": (30, 60),  # 30 scan requests per 60 seconds
    "/api/rag/chat": (60, 60),  # 60 RAG chats per 60 seconds
}
DEFAULT_RATE_LIMIT = (200, 60)  # 200 requests per 60 seconds for everything else


@asynccontextmanager
async def lifespan(app):
    logger.info("Starting VulnDetectRAG v%s", settings.APP_VERSION)
    from config import ensure_dirs

    ensure_dirs()
    init_db()
    logger.info("Database initialized")
    yield
    from services.orchestrator import orchestrator_service

    orchestrator_service.shutdown()
    logger.info("Shutting down VulnDetectRAG")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Centralized Vulnerability Detection & Intelligent Query (RAG) Platform",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Simple per-IP rate limiting."""
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        client_ip = forwarded_for.split(",")[0].strip()
    else:
        client_ip = request.client.host if request.client else "unknown"

    path = request.url.path
    now = time.time()

    # Find matching rate limit
    max_requests, window = DEFAULT_RATE_LIMIT
    for prefix, limit in RATE_LIMITS.items():
        if path.startswith(prefix):
            max_requests, window = limit
            break

    parts = path.strip("/").split("/")
    rate_key = parts[0] if parts else "root"
    key = f"{client_ip}:{rate_key}"

    # Clean up expired entries
    _rate_store[key] = [t for t in _rate_store[key] if now - t < window]

    # Clean up stale keys if dict grows too large
    if len(_rate_store) > 10000:
        stale_keys = [k for k, v in _rate_store.items() if not v or (now - v[-1]) > 60]
        for k in stale_keys:
            _rate_store.pop(k, None)

    if len(_rate_store[key]) >= max_requests:
        return JSONResponse(
            status_code=429,
            content={"detail": "Too many requests. Please try again later."},
        )

    _rate_store[key].append(now)
    return await call_next(request)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    duration = round((time.time() - start) * 1000, 1)
    logger.debug(
        "%s %s → %d (%sms)",
        request.method,
        request.url.path,
        response.status_code,
        duration,
    )
    return response


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Catch all unhandled exceptions and return a clean JSON response."""
    logger.error(
        "Unhandled error on %s %s: %s",
        request.method,
        request.url.path,
        exc,
        exc_info=True,
    )
    return JSONResponse(
        status_code=500,
        content={
            "detail": "An internal server error occurred. Please try again later."
        },
    )


app.include_router(scan_router, prefix="/api")
app.include_router(rag_router, prefix="/api")
app.include_router(cve_router, prefix="/api")


@app.get("/")
async def root():
    return {
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "running",
    }


@app.get("/api/health")
async def health():
    from scanners.nmap_scanner import NmapScanner
    from scanners.nuclei_scanner import NucleiScanner
    from scanners.openvas_scanner import OpenVASScanner
    from scanners.nessus_scanner import NessusScanner

    scanners = {
        "nmap": NmapScanner().is_available(),
        "nuclei": NucleiScanner().is_available(),
        "openvas": OpenVASScanner().is_available(),
        "nessus": NessusScanner().is_available(),
    }
    return {
        "status": "healthy",
        "version": settings.APP_VERSION,
        "scanners": scanners,
    }


@app.get("/api/llm-status")
async def llm_status():
    """Check if a local LLM is available via Ollama."""
    import sys
    import os
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    from rag_assistant.llm_config import LLMFactory
    
    status = LLMFactory.check_ollama_available()
    return status


@app.get("/api/logs")
async def get_logs():
    """Retrieve backend logs."""
    try:
        with open("backend.log", "r") as f:
            lines = f.readlines()
        # Return last 500 lines
        return {"logs": "".join(lines[-500:])}
    except Exception as e:
        return {"logs": f"Could not read logs: {e}"}


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
