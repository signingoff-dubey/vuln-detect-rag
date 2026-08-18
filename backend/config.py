from pathlib import Path
from pydantic_settings import BaseSettings

# Anchor data paths to this file so they never depend on the working directory.
BACKEND_DIR = Path(__file__).resolve().parent
DATA_DIR = BACKEND_DIR / "data"


class Settings(BaseSettings):
    APP_NAME: str = "VulnDetectRAG"
    APP_VERSION: str = "2.0.0"
    DEBUG: bool = True

    # Database
    DATABASE_URL: str = f"sqlite:///{(DATA_DIR / 'vulndetect.db').as_posix()}"

    # Vector DB
    CHROMA_PERSIST_DIR: str = str(DATA_DIR / "chroma")
    CHROMA_COLLECTION: str = "cve_knowledge"

    # Ollama Local LLM
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "qwen3.5:9b"

    # Embedding (local)
    USE_LOCAL_EMBEDDINGS: bool = True
    LOCAL_EMBEDDING_MODEL: str = "all-MiniLM-L6-v2"

    # CORS
    CORS_ORIGINS: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    # Scanner paths
    NMAP_PATH: str = "nmap"
    NUCLEI_PATH: str = "nuclei"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()


def ensure_dirs():
    """Create data directories. Called during app startup."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    Path(settings.CHROMA_PERSIST_DIR).mkdir(parents=True, exist_ok=True)
