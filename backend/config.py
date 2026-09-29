import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


# Get absolute paths based on project root
PROJECT_ROOT = Path(__file__).parent.parent.absolute()
DATA_DIR = PROJECT_ROOT / "backend" / "data"


def _to_sqlite_path(path: Path) -> str:
    """Convert path to SQLite-compatible format (forward slashes)."""
    return str(path).replace("\\", "/")


def _parse_cors_origins(origins_str: str | None) -> list[str]:
    """Parse comma-separated CORS origins from environment variable."""
    default_origins = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
    ]
    if not origins_str:
        return default_origins
    return [origin.strip() for origin in origins_str.split(",") if origin.strip()]


class Settings(BaseSettings):
    APP_NAME: str = "VulnDetectRAG"
    APP_VERSION: str = "4.5.0"
    DEBUG: bool = False

    # Database - use absolute path with forward slashes for SQLite
    DATABASE_URL: str = f"sqlite:///{_to_sqlite_path(DATA_DIR)}/vulndetect.db"

    # Vector DB
    CHROMA_PERSIST_DIR: str = str(DATA_DIR / "chroma")
    # Must match what the RAG package reads. A mismatch between the collection
    # written at index time and the one queried at retrieval time makes the
    # assistant silently retrieve nothing.
    CHROMA_COLLECTION: str = "cve_knowledge"

    # LLM Provider: auto | groq | gemini | ollama | openai | huggingface
    # "auto" picks the first provider in LLM_PROVIDER_ORDER that is configured.
    LLM_PROVIDER: str = "auto"
    LLM_PROVIDER_ORDER: str = "groq,gemini,openrouter,nvidia,ollama"
    # Fall through to the next provider when one is rate-limited or offline.
    LLM_FALLBACK: bool = True

    # Generation tuning
    LLM_TEMPERATURE: float = 0.1
    LLM_MAX_TOKENS: int = 2000
    LLM_CONTEXT_WINDOW: int = 8192
    LLM_TIMEOUT: int = 180
    # Reasoning models spend their token budget on chain-of-thought and can
    # return an empty answer; disabled by default.
    LLM_THINKING: bool = False

    # Ollama Local LLM (offline fallback).
    # Empty OLLAMA_MODEL means auto-select the best installed local model.
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = ""
    OLLAMA_EMBEDDING_MODEL: str = "nomic-embed-text"

    # Groq API (free tier) — https://console.groq.com/keys
    GROQ_API_KEY: str = ""
    GROQ_MODEL: str = "openai/gpt-oss-120b"

    # Google Gemini API (free tier) — https://aistudio.google.com/apikey
    GEMINI_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-flash-latest"

    # OpenRouter (free-tier models only) — https://openrouter.ai/keys
    # The client refuses any model that is not zero-cost.
    OPENROUTER_API_KEY: str = ""
    OPENROUTER_MODEL: str = "openrouter/free"
    OPENROUTER_SITE_URL: str = "http://localhost:5173"
    OPENROUTER_APP_NAME: str = "VulnDetectRAG"

    # NVIDIA NIM (free tier) — https://build.nvidia.com
    NVIDIA_API_KEY: str = ""
    NVIDIA_MODEL: str = "nvidia/nemotron-3-super-120b-a12b"

    # Ensemble orchestration
    LLM_ENSEMBLE: bool = True
    LLM_ENSEMBLE_MODE: str = "synthesize"

    # OpenAI / HuggingFace (optional)
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-4o"
    HUGGINGFACE_API_KEY: str = ""
    HUGGINGFACE_MODEL: str = ""

    # Embedding (local by default, so the corpus never leaves the machine)
    EMBEDDING_PROVIDER: str = "local"
    USE_LOCAL_EMBEDDINGS: bool = True
    LOCAL_EMBEDDING_MODEL: str = "all-MiniLM-L6-v2"

    # Retrieval tuning
    RAG_SCORE_THRESHOLD: float = 0.25
    RAG_OVERFETCH: int = 4
    RAG_CONTEXT_BUDGET: int = 6000
    RAG_HISTORY_BUDGET: int = 2000

    # Sharded reading: split retrieved documents across the cloud providers so
    # each is charged for a fraction of the context instead of all of it.
    RAG_MAP_REDUCE: bool = True
    RAG_SHARD_CHARS: int = 2500
    RAG_MIN_DOCS_TO_SHARD: int = 3
    RAG_MAX_SHARDS: int = 6
    # Shorter than LLM_TIMEOUT on purpose: an unreachable provider blocks for
    # its full HTTP read timeout without erroring, and waiting that out delays
    # every other provider's answer for nothing.
    RAG_MAP_TIMEOUT: int = 90

    # Post-hoc grounding verification of the finished answer.
    RAG_VERIFY: bool = True
    RAG_VERIFY_REPAIR: bool = True

    # CORS - support environment override with comma-separated list
    # Set CORS_ORIGINS env var with comma-separated URLs
    CORS_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
    ]
    CORS_ORIGINS_ENV: str = ""  # Set via environment variable

    # When set, every /api request except /api/health must send this value in
    # the X-API-Key header. Leave empty only while bound to loopback.
    API_KEY: str = ""
    # Honour X-Forwarded-For for rate limiting. Enable only behind a trusted
    # reverse proxy that overwrites the header.
    TRUST_PROXY_HEADERS: bool = False

    # Scanner paths - will be auto-detected if not set
    NMAP_PATH: str = ""
    NUCLEI_PATH: str = ""
    OPENVAS_PATH: str = ""
    NESSUS_PATH: str = ""
    BURP_PATH: str = ""  # Burp Suite
    ZAP_PATH: str = ""  # OWASP ZAP

    model_config = SettingsConfigDict(
        env_file=(
            str(PROJECT_ROOT / ".env"),
            str(PROJECT_ROOT / "backend" / ".env"),
        ),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Parse CORS origins from environment if set
        env_origins = os.environ.get("CORS_ORIGINS", "")
        if env_origins:
            self.CORS_ORIGINS = _parse_cors_origins(env_origins)
        elif self.CORS_ORIGINS_ENV:
            self.CORS_ORIGINS = _parse_cors_origins(self.CORS_ORIGINS_ENV)

        # The rag_assistant package is standalone and reads its configuration
        # from the environment. Settings loaded from .env land in this object,
        # not in os.environ, so they are republished here — otherwise the
        # backend and the RAG package would silently disagree.
        self._publish_to_environment()

    def _publish_to_environment(self) -> None:
        """Export settings the standalone rag_assistant package reads."""
        exported = {
            "LLM_PROVIDER": self.LLM_PROVIDER,
            "LLM_PROVIDER_ORDER": self.LLM_PROVIDER_ORDER,
            "LLM_FALLBACK": "1" if self.LLM_FALLBACK else "0",
            "LLM_TEMPERATURE": str(self.LLM_TEMPERATURE),
            "LLM_MAX_TOKENS": str(self.LLM_MAX_TOKENS),
            "LLM_CONTEXT_WINDOW": str(self.LLM_CONTEXT_WINDOW),
            "LLM_TIMEOUT": str(self.LLM_TIMEOUT),
            "LLM_THINKING": "1" if self.LLM_THINKING else "0",
            "OLLAMA_BASE_URL": self.OLLAMA_BASE_URL,
            "OLLAMA_MODEL": self.OLLAMA_MODEL,
            "OLLAMA_EMBEDDING_MODEL": self.OLLAMA_EMBEDDING_MODEL,
            "GROQ_API_KEY": self.GROQ_API_KEY,
            "GROQ_MODEL": self.GROQ_MODEL,
            "GEMINI_API_KEY": self.GEMINI_API_KEY,
            "GEMINI_MODEL": self.GEMINI_MODEL,
            "OPENROUTER_API_KEY": self.OPENROUTER_API_KEY,
            "OPENROUTER_MODEL": self.OPENROUTER_MODEL,
            "OPENROUTER_SITE_URL": self.OPENROUTER_SITE_URL,
            "OPENROUTER_APP_NAME": self.OPENROUTER_APP_NAME,
            "NVIDIA_API_KEY": self.NVIDIA_API_KEY,
            "NVIDIA_MODEL": self.NVIDIA_MODEL,
            "LLM_ENSEMBLE": "1" if self.LLM_ENSEMBLE else "0",
            "LLM_ENSEMBLE_MODE": self.LLM_ENSEMBLE_MODE,
            "OPENAI_API_KEY": self.OPENAI_API_KEY,
            "OPENAI_MODEL": self.OPENAI_MODEL,
            "HUGGINGFACE_API_KEY": self.HUGGINGFACE_API_KEY,
            "HUGGINGFACE_MODEL": self.HUGGINGFACE_MODEL,
            "EMBEDDING_PROVIDER": self.EMBEDDING_PROVIDER,
            "LOCAL_EMBEDDING_MODEL": self.LOCAL_EMBEDDING_MODEL,
            "CHROMA_COLLECTION": self.CHROMA_COLLECTION,
            "VECTOR_STORE_PATH": self.CHROMA_PERSIST_DIR,
            "RAG_SCORE_THRESHOLD": str(self.RAG_SCORE_THRESHOLD),
            "RAG_OVERFETCH": str(self.RAG_OVERFETCH),
            "RAG_CONTEXT_BUDGET": str(self.RAG_CONTEXT_BUDGET),
            "RAG_HISTORY_BUDGET": str(self.RAG_HISTORY_BUDGET),
            "RAG_MAP_REDUCE": "1" if self.RAG_MAP_REDUCE else "0",
            "RAG_SHARD_CHARS": str(self.RAG_SHARD_CHARS),
            "RAG_MIN_DOCS_TO_SHARD": str(self.RAG_MIN_DOCS_TO_SHARD),
            "RAG_MAX_SHARDS": str(self.RAG_MAX_SHARDS),
            "RAG_MAP_TIMEOUT": str(self.RAG_MAP_TIMEOUT),
            "RAG_VERIFY": "1" if self.RAG_VERIFY else "0",
            "RAG_VERIFY_REPAIR": "1" if self.RAG_VERIFY_REPAIR else "0",
        }
        for key, value in exported.items():
            # A real environment variable always wins over the .env file.
            if value not in ("", None) and not os.environ.get(key):
                os.environ[key] = str(value)


settings = Settings()

from services.tool_paths import ensure_tools_on_path  # noqa: E402

ensure_tools_on_path()


def ensure_dirs():
    """Create data directories. Called during app startup."""
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
    except PermissionError as e:
        import logging

        logging.warning(f"Cannot create data directory: {e}. Using fallback location.")
        Path("./data").mkdir(exist_ok=True)

    chroma_dir = Path(settings.CHROMA_PERSIST_DIR)
    try:
        chroma_dir.mkdir(parents=True, exist_ok=True)
    except PermissionError as e:
        import logging

        logging.warning(f"Cannot create chroma directory: {e}")
        # Fallback to default location
        settings.CHROMA_PERSIST_DIR = str(DATA_DIR / "chroma")
        (DATA_DIR / "chroma").mkdir(parents=True, exist_ok=True)
