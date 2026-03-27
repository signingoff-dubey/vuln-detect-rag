from pathlib import Path
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    APP_NAME: str = "VulnDetectRAG"
    APP_VERSION: str = "1.3.0"
    DEBUG: bool = True

    # Database
    DATABASE_URL: str = "sqlite:///./data/vulndetect.db"

    # Vector DB
    CHROMA_PERSIST_DIR: str = "./data/chroma"
    CHROMA_COLLECTION: str = "cve_knowledge"

    # Ollama Local LLM
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "qwen2.5-coder:7b"

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
    Path("./data").mkdir(exist_ok=True)
    Path(settings.CHROMA_PERSIST_DIR).mkdir(parents=True, exist_ok=True)
