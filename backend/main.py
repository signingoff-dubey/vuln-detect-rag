import json
import hmac
import logging
import os
import threading
import time
from collections import defaultdict
import uvicorn
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pathlib import Path

from config import settings
from models.database import init_db
from api.routes_scan import router as scan_router
from api.routes_rag import router as rag_router
from api.routes_cve import router as cve_router
from api.routes_graph import router as graph_router
from api.routes_sanitize import router as sanitize_router

# Use absolute path for log file in data directory
LOG_DIR = Path(__file__).parent / "data"
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "backend.log"

logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()],
)
logger = logging.getLogger("vulndetect")


# Simple in-memory rate limiter
_rate_store: dict[str, list[float]] = defaultdict(list)
RATE_LIMITS = {
    "/api/scans": (30, 60),  # 30 scan requests per 60 seconds
    "/api/rag/chat": (60, 60),  # 60 RAG chats per 60 seconds
}
DEFAULT_RATE_LIMIT = (200, 60)  # 200 requests per 60 seconds for everything else


def _warm_provider_caches() -> None:
    """Populate the provider caches in the background at startup.

    ``/api/providers`` enumerates each configured provider's model catalogue
    and probes Ollama. Both are cached, but the first caller pays for filling
    those caches -- which is always the dashboard's first paint, so the cost
    landed exactly where it was most visible.

    Warming runs on a daemon thread rather than inside the lifespan body: the
    work is network-bound and unnecessary for the server to be correct, so it
    must not delay the port opening. Every failure is swallowed for the same
    reason -- a provider that cannot be reached at startup is a condition the
    endpoints already report per provider, not a reason to fail boot.
    """
    def warm():
        from rag_assistant.llm_config import LLMFactory

        try:
            LLMFactory.check_ollama_available()
        except Exception:
            logger.debug("Ollama warm-up failed", exc_info=True)

        for name in ("groq", "gemini", "openrouter", "nvidia"):
            try:
                if LLMFactory.is_configured(name):
                    LLMFactory.list_models(name)
            except Exception:
                logger.debug("Catalogue warm-up failed for %s", name,
                             exc_info=True)

    threading.Thread(target=warm, name="provider-warmup",
                     daemon=True).start()


@asynccontextmanager
async def lifespan(app):
    logger.info("Starting VulnDetectRAG v%s", settings.APP_VERSION)
    _load_provider_prefs()
    from config import ensure_dirs

    ensure_dirs()
    init_db()
    logger.info("Database initialized")
    from services.orchestrator import orchestrator_service as _orch

    interrupted = _orch.fail_interrupted_scans()
    if interrupted:
        logger.warning("Marked %d interrupted scan(s) as failed", interrupted)
    _warm_provider_caches()
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
    allow_credentials="*" not in settings.CORS_ORIGINS,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "Accept", "X-API-Key"],
)


_AUTH_EXEMPT = {"/api/health"}


@app.middleware("http")
async def api_key_middleware(request: Request, call_next):
    if (
        settings.API_KEY
        and request.method != "OPTIONS"
        and request.url.path.startswith("/api")
        and request.url.path not in _AUTH_EXEMPT
    ):
        supplied = request.headers.get("x-api-key", "")
        if not hmac.compare_digest(supplied.encode(), settings.API_KEY.encode()):
            return JSONResponse(status_code=401, content={"detail": "Invalid or missing API key"})
    return await call_next(request)


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Simple per-IP rate limiting."""
    forwarded_for = (
        request.headers.get("x-forwarded-for") if settings.TRUST_PROXY_HEADERS else None
    )
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
app.include_router(graph_router, prefix="/api")
app.include_router(sanitize_router, prefix="/api")


@app.get("/")
async def root():
    return {
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "running",
    }


@app.get("/api/health")
async def health():
    from services.orchestrator import SCANNER_MAP

    # Availability is probed per scanner so the UI can distinguish a tool that
    # will run live from one that will return simulated data.
    scanners = {}
    detail = {}
    for key, scanner_cls in SCANNER_MAP.items():
        try:
            instance = scanner_cls()
            available = instance.is_available()
        except Exception:
            logger.exception("Availability check failed for %s", key)
            available = False
            instance = None

        scanners[key] = available
        detail[key] = {
            "available": available,
            "free": getattr(scanner_cls, "free", True),
            "requires_licence": getattr(scanner_cls, "requires_licence", False),
            "licence_note": getattr(scanner_cls, "licence_note", ""),
            "install_hint": getattr(instance, "install_hint", "") if instance else "",
        }

    return {
        "status": "healthy",
        "version": settings.APP_VERSION,
        "scanners": scanners,
        "scanner_detail": detail,
    }


@app.get("/api/llm-status")
async def llm_status():
    """Report which LLM backends are usable and which one will serve requests.

    Covers every provider rather than only Ollama, so the UI can tell the user
    that the assistant works via a cloud key even with no local model, instead
    of showing a bare "Local LLM Not Found".
    """
    from rag_assistant.llm_config import LLMFactory

    ollama = LLMFactory.check_ollama_available()

    providers = []
    for name in LLMFactory.provider_order():
        configured = LLMFactory.is_configured(name)
        entry = {
            "provider": name,
            "configured": configured,
            "local": name == "ollama",
        }
        if name == "ollama":
            entry["model"] = ollama.get("model", "")
            entry["models"] = ollama.get("models", [])
            entry["error"] = ollama.get("error", "")
        elif configured:
            entry["model"] = {
                "groq": settings.GROQ_MODEL,
                "gemini": settings.GEMINI_MODEL,
                "openai": settings.OPENAI_MODEL,
                "huggingface": settings.HUGGINGFACE_MODEL,
            }.get(name, "")
        providers.append(entry)

    active = next((p for p in providers if p["configured"]), None)

    return {
        # Kept for backward compatibility with the existing frontend, which
        # reads these top-level Ollama fields.
        **ollama,
        "available": bool(active),
        "active_provider": active["provider"] if active else "",
        "active_model": active.get("model", "") if active else "",
        "is_local": active["local"] if active else False,
        "fallback_enabled": settings.LLM_FALLBACK,
        "providers": providers,
        "ollama": ollama,
    }


#: Where provider toggles are persisted, so a research run's configuration
#: survives a restart and can be recorded alongside its results.
PROVIDER_PREFS_FILE = LOG_DIR / "provider_prefs.json"


def _load_provider_prefs() -> None:
    """Restore provider toggles saved by a previous run."""
    import json

    if not PROVIDER_PREFS_FILE.exists():
        return
    try:
        with open(PROVIDER_PREFS_FILE, "r", encoding="utf-8") as handle:
            disabled = json.load(handle).get("disabled", [])
        if disabled:
            os.environ["LLM_DISABLED_PROVIDERS"] = ",".join(disabled)
            logger.info("Restored disabled LLM providers: %s", ", ".join(disabled))

        with open(PROVIDER_PREFS_FILE, "r", encoding="utf-8") as handle:
            prefs = json.load(handle)
        if "rag_enabled" in prefs:
            os.environ["RAG_ENABLED"] = "1" if prefs["rag_enabled"] else "0"
            logger.info("Restored retrieval enabled=%s", prefs["rag_enabled"])
    except Exception:
        logger.exception("Could not read provider preferences")


def _rebuild_llm_stack() -> None:
    """Invalidate every cached LLM client so a settings change takes effect.

    Three layers cache a client: the pipeline cache in rag_chain, the singleton
    in rag_engine, and any pipeline a request already resolved. Clearing only
    one of them leaves a stale provider serving requests, which is what makes a
    toggle look broken.
    """
    try:
        from services.rag_engine import rag_engine

        rag_engine.reset()
    except Exception:
        logger.exception("Could not reset the RAG engine")
        from rag_assistant.chains.rag_chain import reset_pipelines

        reset_pipelines()


def _save_provider_prefs(disabled) -> None:
    """Persist provider toggles."""
    import json

    try:
        with open(PROVIDER_PREFS_FILE, "w", encoding="utf-8") as handle:
            json.dump({"disabled": sorted(disabled)}, handle)
    except Exception:
        logger.exception("Could not save provider preferences")


@app.get("/api/providers")
async def list_providers():
    """List every LLM provider with its configuration and enabled state."""
    from rag_assistant.llm_config import LLMFactory

    disabled = LLMFactory.disabled_providers()
    model_by_provider = {
        "groq": settings.GROQ_MODEL,
        "gemini": settings.GEMINI_MODEL,
        "openrouter": settings.OPENROUTER_MODEL,
        "nvidia": settings.NVIDIA_MODEL,
        "openai": settings.OPENAI_MODEL,
        "huggingface": settings.HUGGINGFACE_MODEL,
    }
    key_by_provider = {
        "groq": settings.GROQ_API_KEY,
        "gemini": settings.GEMINI_API_KEY,
        "openrouter": settings.OPENROUTER_API_KEY,
        "nvidia": settings.NVIDIA_API_KEY,
        "openai": settings.OPENAI_API_KEY,
        "huggingface": settings.HUGGINGFACE_API_KEY,
    }

    providers = []
    # The four free cloud backends plus the local one, in preference order.
    for name in ("groq", "gemini", "openrouter", "nvidia", "ollama"):
        enabled = name not in disabled
        has_key = name == "ollama" or bool(key_by_provider.get(name))

        entry = {
            "provider": name,
            "enabled": enabled,
            "has_credentials": has_key,
            "local": name == "ollama",
            "model": model_by_provider.get(name, ""),
            "free_tier": True,
            "model_count": 0,
        }
        # Only enumerate models for providers that could actually serve a
        # request; listing costs a network round trip.
        if enabled and has_key:
            try:
                entry["model_count"] = len(LLMFactory.list_models(name))
            except Exception:
                entry["model_count"] = 0
        if name == "ollama":
            status = LLMFactory.check_ollama_available()
            entry["model"] = status.get("model", "")
            entry["has_credentials"] = status.get("available", False)
            entry["error"] = status.get("error", "")
        providers.append(entry)

    active = next(
        (p["provider"] for p in providers if p["enabled"] and p["has_credentials"]),
        "",
    )

    return {
        "providers": providers,
        "active_provider": active,
        "ensemble_enabled": settings.LLM_ENSEMBLE,
        "ensemble_mode": settings.LLM_ENSEMBLE_MODE,
        "fallback_enabled": settings.LLM_FALLBACK,
        "order": LLMFactory.provider_order(),
    }


@app.post("/api/providers/{provider}")
async def toggle_provider(provider: str, enabled: bool = True):
    """Enable or disable one LLM provider at runtime.

    Exists so a research run can isolate a single backend — comparing Groq
    against Gemini is only meaningful if the others can be switched off.
    """
    from fastapi import HTTPException
    from rag_assistant.llm_config import LLMFactory

    try:
        disabled = LLMFactory.set_provider_enabled(provider, enabled)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    _save_provider_prefs(disabled)

    _rebuild_llm_stack()

    return {
        "provider": provider,
        "enabled": enabled,
        "disabled_providers": sorted(disabled),
        "order": LLMFactory.provider_order(),
    }


@app.get("/api/providers/{provider}/models")
async def list_provider_models(provider: str):
    """List the models a provider currently offers.

    Lets the UI offer a real choice rather than a hardcoded list that goes
    stale whenever a provider retires a model.
    """
    from fastapi import HTTPException
    from rag_assistant.llm_config import LLMFactory

    if provider not in LLMFactory.PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Unknown provider: {provider}")

    current = {
        "groq": settings.GROQ_MODEL,
        "gemini": settings.GEMINI_MODEL,
        "openrouter": settings.OPENROUTER_MODEL,
        "nvidia": settings.NVIDIA_MODEL,
    }.get(provider, os.environ.get(f"{provider.upper()}_MODEL", ""))

    return {
        "provider": provider,
        "current": os.environ.get(f"{provider.upper()}_MODEL", current),
        "models": LLMFactory.list_models(provider),
    }


@app.post("/api/providers/{provider}/model")
async def set_provider_model(provider: str, model: str):
    """Pin which model a provider should use.

    Model choice is the main independent variable in an LLM comparison, so it
    has to be changeable without editing configuration and restarting.
    """
    from fastapi import HTTPException
    from rag_assistant.llm_config import LLMFactory

    if provider not in LLMFactory.PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Unknown provider: {provider}")

    available = LLMFactory.list_models(provider)
    if available and model not in available:
        raise HTTPException(
            status_code=400,
            detail=f"Model '{model}' is not offered by {provider}.",
        )

    os.environ[f"{provider.upper()}_MODEL"] = model
    _rebuild_llm_stack()
    logger.info("Provider %s pinned to model %s", provider, model)

    return {"provider": provider, "model": model}


@app.get("/api/rag-config")
async def get_rag_config():
    """Report whether retrieval is enabled, and the corpus it would search."""
    from rag_assistant.chains.rag_chain import RAGPipeline

    document_count = 0
    try:
        from services.rag_engine import rag_engine

        document_count = rag_engine.vector_store.count()
    except Exception:
        logger.exception("Could not count vector store documents")

    return {
        "rag_enabled": RAGPipeline.retrieval_enabled(),
        "documents": document_count,
        "collection": settings.CHROMA_COLLECTION,
        "embedding_model": settings.LOCAL_EMBEDDING_MODEL,
        "score_threshold": settings.RAG_SCORE_THRESHOLD,
    }


@app.post("/api/rag-config")
async def set_rag_config(enabled: bool = True):
    """Turn retrieval on or off.

    With retrieval off the assistant answers purely from the model's own
    knowledge — the no-RAG baseline needed to show what the knowledge base
    contributes.
    """
    os.environ["RAG_ENABLED"] = "1" if enabled else "0"
    _rebuild_llm_stack()

    try:
        with open(PROVIDER_PREFS_FILE, "r", encoding="utf-8") as handle:
            prefs = json.load(handle)
    except Exception:
        prefs = {}
    prefs["rag_enabled"] = enabled
    try:
        with open(PROVIDER_PREFS_FILE, "w", encoding="utf-8") as handle:
            json.dump(prefs, handle)
    except Exception:
        logger.exception("Could not persist RAG toggle")

    logger.info("Retrieval %s", "enabled" if enabled else "disabled")
    return {"rag_enabled": enabled}


@app.get("/api/eval-metrics")
async def eval_metrics():
    """Serve the most recent evaluation results.

    Reports only what `scripts/run_eval.py` actually measured. If that script
    has not been run there are no metrics to show, and this says so rather than
    inventing placeholders — the defect that made the previous metrics display
    misleading.
    """
    results_file = LOG_DIR / "eval_results.json"
    if not results_file.exists():
        return {
            "available": False,
            "message": (
                "No evaluation has been run yet. Run: "
                "python scripts/run_eval.py --ablation"
            ),
        }

    try:
        with open(results_file, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except Exception as e:
        logger.exception("Could not read evaluation results")
        return {"available": False, "message": f"Could not read results: {e}"}

    metrics = payload.get("metrics", {})
    environment = payload.get("environment", {})

    # Records are the per-question detail; they are large and the UI does not
    # need them, so only the summary is returned.
    return {
        "available": True,
        "environment": environment,
        "metrics": metrics,
        "limitations": payload.get("limitations", []),
        "conditions": list(metrics.keys()),
    }


@app.get("/api/logs")
async def get_logs():
    """Retrieve backend logs."""
    try:
        with open(str(LOG_FILE), "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        return {"logs": "".join(lines[-500:])}
    except Exception as e:
        return {"logs": f"Could not read logs: {e}"}


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=settings.DEBUG)
