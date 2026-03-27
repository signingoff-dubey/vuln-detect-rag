"""Embedding utilities for text vectorization."""

import os
import hashlib
import logging
from typing import List, Optional, Callable
from functools import lru_cache

logger = logging.getLogger(__name__)


class EmbeddingService:
    """Service for generating text embeddings."""
    
    def __init__(self, provider: Optional[str] = None, model: Optional[str] = None):
        """Initialize embedding service.
        
        Args:
            provider: Embedding provider (openai, local)
            model: Embedding model name
        """
        self.provider = provider or os.getenv('EMBEDDING_PROVIDER', 'local')
        self.model = model or os.getenv('LOCAL_EMBEDDING_MODEL', 'all-MiniLM-L6-v2')
        self._embedding_fn: Optional[Callable] = None
    
    @property
    def embedding_fn(self) -> Callable:
        """Get embedding function."""
        if self._embedding_fn is None:
            self._embedding_fn = self._get_embedding_function()
        return self._embedding_fn
    
    def _get_embedding_function(self) -> Callable:
        """Get appropriate embedding function based on provider."""
        if self.provider == 'openai':
            return self._openai_embedding
        elif self.provider == 'huggingface':
            return self._huggingface_embedding
        elif self.provider == 'ollama':
            return self._ollama_embedding
        elif self.provider == 'local':
            return self._local_embedding
        else:
            return self._local_embedding
    
    def _openai_embedding(self, text: str) -> List[float]:
        """Generate embedding using OpenAI."""
        try:
            from openai import OpenAI
            
            api_key = os.getenv('OPENAI_API_KEY')
            if not api_key:
                raise ValueError("OPENAI_API_KEY not set")
            
            client = OpenAI(api_key=api_key)
            
            response = client.embeddings.create(
                model=self.model,
                input=text
            )
            
            return response.data[0].embedding
            
        except ImportError:
            logger.error("OpenAI package not installed")
            raise
        except Exception as e:
            logger.error(f"OpenAI embedding error: {e}")
            raise
    
    def _huggingface_embedding(self, text: str) -> List[float]:
        """Generate embedding using Hugging Face."""
        try:
            import requests
            
            api_key = os.getenv('HUGGINGFACE_API_KEY')
            if not api_key:
                raise ValueError("HUGGINGFACE_API_KEY not set")
            
            headers = {"Authorization": f"Bearer {api_key}"}
            
            response = requests.post(
                "https://api-inference.huggingface.co/pipeline/feature-extraction",
                headers=headers,
                json={"inputs": text},
                timeout=30
            )
            
            if response.status_code == 200:
                embedding = response.json()
                if isinstance(embedding, list) and len(embedding) > 0:
                    if isinstance(embedding[0], list):
                        return embedding[0]
                    return embedding
            else:
                raise Exception(f"HuggingFace API error: {response.status_code}")
                
        except Exception as e:
            logger.error(f"HuggingFace embedding error: {e}")
            raise
    
    def _ollama_embedding(self, text: str) -> List[float]:
        """Generate embedding using Ollama."""
        try:
            import ollama
            
            base_url = os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434')
            
            response = ollama.embeddings(
                model=self.model or 'nomic-embed-text',
                prompt=text
            )
            
            return response['embedding']
            
        except ImportError:
            logger.error("Ollama package not installed")
            raise
        except Exception as e:
            logger.error(f"Ollama embedding error: {e}")
            raise
    
    def _local_embedding(self, text: str) -> List[float]:
        """Generate embedding using local HuggingFace sentence-transformers."""
        try:
            # We cache the embedding model on the instance so we don't reload it every call
            if not hasattr(self, "_hf_embeddings"):
                from langchain_huggingface import HuggingFaceEmbeddings
                self._hf_embeddings = HuggingFaceEmbeddings(model_name=self.model)
            return self._hf_embeddings.embed_query(text)
        except ImportError:
            logger.error("langchain_huggingface or sentence-transformers not installed")
            raise
        except Exception as e:
            logger.error(f"Local embedding error: {e}")
            raise
    
    def embed(self, text: str) -> List[float]:
        """Generate embedding for text.
        
        Args:
            text: Text to embed
            
        Returns:
            Embedding vector
        """
        return self.embedding_fn(text)
    
    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings for multiple texts.
        
        Args:
            texts: List of texts to embed
            
        Returns:
            List of embedding vectors
        """
        return [self.embed(text) for text in texts]
    
    @staticmethod
    def chunk_text(text: str, chunk_size: int = 500, overlap: int = 50) -> List[str]:
        """Split text into overlapping chunks.
        
        Args:
            text: Text to chunk
            chunk_size: Maximum chunk size in characters
            overlap: Overlap between chunks
            
        Returns:
            List of text chunks
        """
        if len(text) <= chunk_size:
            return [text]
        
        chunks = []
        start = 0
        
        while start < len(text):
            end = start + chunk_size
            
            if end < len(text):
                last_period = text.rfind('.', start + chunk_size // 2, end)
                last_newline = text.rfind('\n', start + chunk_size // 2, end)
                split_point = max(last_period, last_newline)
                
                if split_point > start + chunk_size // 4:
                    end = split_point + 1
                else:
                    end = start + chunk_size
            
            chunk = text[start:end].strip()
            if chunk:
                chunks.append(chunk)
            
            start = end - overlap if end < len(text) else end
        
        return chunks


class EmbeddingCache:
    """Cache for storing computed embeddings."""
    
    def __init__(self, max_size: int = 1000):
        """Initialize embedding cache.
        
        Args:
            max_size: Maximum cache size
        """
        self.max_size = max_size
        self._cache: dict = {}
    
    def get(self, text: str) -> Optional[List[float]]:
        """Get cached embedding.
        
        Args:
            text: Text to look up
            
        Returns:
            Cached embedding or None
        """
        key = self._hash_text(text)
        return self._cache.get(key)
    
    def set(self, text: str, embedding: List[float]) -> None:
        """Cache embedding.
        
        Args:
            text: Text key
            embedding: Embedding to cache
        """
        if len(self._cache) >= self.max_size:
            oldest_key = next(iter(self._cache))
            del self._cache[oldest_key]
        
        key = self._hash_text(text)
        self._cache[key] = embedding
    
    @staticmethod
    def _hash_text(text: str) -> str:
        """Generate hash for text."""
        return hashlib.md5(text.encode()).hexdigest()


def get_embedding_service(provider: Optional[str] = None) -> EmbeddingService:
    """Get configured embedding service.
    
    Args:
        provider: Optional provider override
        
    Returns:
        EmbeddingService instance
    """
    return EmbeddingService(provider=provider)
