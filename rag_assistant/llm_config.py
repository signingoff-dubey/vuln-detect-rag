"""LLM configuration and factory for multiple providers."""

import os
import logging
from typing import Optional, Dict, Any, Union
from abc import ABC, abstractmethod
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class LLMConfig:
    """LLM provider configuration."""
    provider: str
    model: str
    temperature: float = 0.0
    max_tokens: int = 2000
    api_key: Optional[str] = None
    base_url: Optional[str] = None


class BaseLLMClient(ABC):
    """Abstract base class for LLM clients."""
    
    def __init__(self, config: LLMConfig):
        """Initialize LLM client.
        
        Args:
            config: LLM configuration
        """
        self.config = config
    
    @abstractmethod
    def generate(self, prompt: str, **kwargs) -> str:
        """Generate text from prompt.
        
        Args:
            prompt: Input prompt
            **kwargs: Additional generation parameters
            
        Returns:
            Generated text
        """
        pass
    
    @abstractmethod
    def get_embedding(self, text: str) -> list:
        """Get embedding for text.
        
        Args:
            text: Text to embed
            
        Returns:
            Embedding vector
        """
        pass


class OpenAIClient(BaseLLMClient):
    """OpenAI GPT client."""
    
    def __init__(self, config: LLMConfig):
        """Initialize OpenAI client."""
        super().__init__(config)
        self._client = None
    
    @property
    def client(self):
        """Get or create OpenAI client."""
        if self._client is None:
            try:
                from openai import OpenAI
                self._client = OpenAI(api_key=self.config.api_key)
            except ImportError:
                logger.error("OpenAI package not installed")
                raise
        return self._client
    
    def generate(self, prompt: str, **kwargs) -> str:
        """Generate text using OpenAI."""
        try:
            response = self.client.chat.completions.create(
                model=self.config.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=kwargs.get('temperature', self.config.temperature),
                max_tokens=kwargs.get('max_tokens', self.config.max_tokens)
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"OpenAI generation error: {e}")
            raise
    
    def get_embedding(self, text: str) -> list:
        """Get embedding using OpenAI."""
        try:
            response = self.client.embeddings.create(
                model="text-embedding-3-small",
                input=text
            )
            return response.data[0].embedding
        except Exception as e:
            logger.error(f"OpenAI embedding error: {e}")
            raise


class OllamaClient(BaseLLMClient):
    """Ollama local LLM client."""
    
    def __init__(self, config: LLMConfig):
        """Initialize Ollama client."""
        super().__init__(config)
        self.base_url = config.base_url or os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434')
        self._client = None
    
    @property
    def client(self):
        """Get or create Ollama client."""
        if self._client is None:
            try:
                import ollama
                self._client = ollama
            except ImportError:
                logger.error("Ollama package not installed")
                raise
        return self._client
    
    def generate(self, prompt: str, **kwargs) -> str:
        """Generate text using Ollama."""
        try:
            response = self.client.chat(
                model=self.config.model,
                messages=[{"role": "user", "content": prompt}]
            )
            return response['message']['content']
        except Exception as e:
            logger.error(f"Ollama generation error: {e}")
            raise
    
    def get_embedding(self, text: str) -> list:
        """Get embedding using Ollama."""
        try:
            response = self.client.embeddings(
                model=self.config.model,
                prompt=text
            )
            return response['embedding']
        except Exception as e:
            logger.error(f"Ollama embedding error: {e}")
            raise


class GroqClient(BaseLLMClient):
    """Groq cloud LLM client."""
    
    def __init__(self, config: LLMConfig):
        """Initialize Groq client."""
        super().__init__(config)
        self.base_url = "https://api.groq.com/openai/v1"
        self._client = None
    
    @property
    def client(self):
        """Get or create Groq client."""
        if self._client is None:
            try:
                from openai import OpenAI
                self._client = OpenAI(
                    api_key=self.config.api_key,
                    base_url=self.base_url
                )
            except ImportError:
                logger.error("OpenAI package not installed")
                raise
        return self._client
    
    def generate(self, prompt: str, **kwargs) -> str:
        """Generate text using Groq."""
        try:
            response = self.client.chat.completions.create(
                model=self.config.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=kwargs.get('temperature', self.config.temperature),
                max_tokens=kwargs.get('max_tokens', self.config.max_tokens)
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"Groq generation error: {e}")
            raise
    
    def get_embedding(self, text: str) -> list:
        """Get embedding using Groq (uses OpenAI-compatible endpoint)."""
        try:
            response = self.client.embeddings.create(
                model="text-embedding-3-small",
                input=text
            )
            return response.data[0].embedding
        except Exception as e:
            logger.error(f"Groq embedding error: {e}")
            raise


class HuggingFaceClient(BaseLLMClient):
    """Hugging Face Inference API client."""
    
    def __init__(self, config: LLMConfig):
        """Initialize Hugging Face client."""
        super().__init__(config)
        self.base_url = "https://api-inference.huggingface.co/models"
        self._client = None
    
    def generate(self, prompt: str, **kwargs) -> str:
        """Generate text using Hugging Face."""
        try:
            import requests
            
            headers = {"Authorization": f"Bearer {self.config.api_key}"}
            payload = {
                "inputs": prompt,
                "parameters": {
                    "temperature": kwargs.get('temperature', self.config.temperature),
                    "max_new_tokens": kwargs.get('max_tokens', self.config.max_tokens)
                }
            }
            
            response = requests.post(
                f"{self.base_url}/{self.config.model}",
                headers=headers,
                json=payload,
                timeout=120
            )
            
            if response.status_code == 200:
                result = response.json()
                if isinstance(result, list):
                    return result[0].get('generated_text', '')
                return result.get('generated_text', '')
            else:
                raise Exception(f"HuggingFace API error: {response.status_code}")
                
        except Exception as e:
            logger.error(f"HuggingFace generation error: {e}")
            raise
    
    def get_embedding(self, text: str) -> list:
        """Get embedding using Hugging Face."""
        try:
            import requests
            
            headers = {"Authorization": f"Bearer {self.config.api_key}"}
            
            response = requests.post(
                f"{self.base_url}/sentence-transformers/all-MiniLM-L6-v2",
                headers=headers,
                json={"inputs": text},
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()[0]
            else:
                raise Exception(f"HuggingFace embedding error: {response.status_code}")
                
        except Exception as e:
            logger.error(f"HuggingFace embedding error: {e}")
            raise


class LLMFactory:
    """Factory for creating LLM clients."""
    
    @staticmethod
    def check_ollama_available() -> dict:
        """Check if Ollama is running and detect available models."""
        import subprocess
        result = {
            "available": False,
            "model": "",
            "provider": "ollama",
            "models": [],
        }
        try:
            proc = subprocess.run(
                ["ollama", "list"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if proc.returncode != 0:
                return result

            lines = proc.stdout.strip().splitlines()
            for line in lines[1:]:
                parts = line.split()
                if parts:
                    result["models"].append(parts[0])

            configured = os.getenv('OLLAMA_MODEL')
            if configured and configured in result["models"]:
                result["available"] = True
                result["model"] = configured
            elif result["models"]:
                # If configured is not found or not set, pick the first one available
                result["available"] = True
                result["model"] = result["models"][0]

        except Exception as e:
            logger.warning(f"Failed to check Ollama availability: {e}")

        return result
    
    PROVIDERS = {
        'openai': OpenAIClient,
        'ollama': OllamaClient,
        'groq': GroqClient,
        'huggingface': HuggingFaceClient
    }
    
    @classmethod
    def create(cls, provider: Optional[str] = None) -> BaseLLMClient:
        """Create LLM client based on configuration.
        
        Args:
            provider: LLM provider name
            
        Returns:
            LLM client instance
        """
        provider = provider or os.getenv('LLM_PROVIDER', 'ollama').lower()
        
        if provider not in cls.PROVIDERS:
            raise ValueError(f"Unknown LLM provider: {provider}")
        
        if provider == 'ollama':
            # Auto-detect ollama model if not explicitly set
            ollama_status = cls.check_ollama_available()
            default_ollama_model = ollama_status["model"] if ollama_status["available"] else 'qwen2.5-coder:7b'
        else:
            default_ollama_model = 'qwen2.5-coder:7b'

        model_map = {
            'openai': os.getenv('OPENAI_MODEL', 'gpt-4o'),
            'ollama': os.getenv('OLLAMA_MODEL', default_ollama_model),
            'groq': os.getenv('GROQ_MODEL', 'llama-3.1-70b-versatile'),
            'huggingface': os.getenv('HUGGINGFACE_MODEL', 'meta-llama/Llama-3-70b-chat-hf')
        }
        
        api_key_map = {
            'openai': os.getenv('OPENAI_API_KEY'),
            'groq': os.getenv('GROQ_API_KEY'),
            'huggingface': os.getenv('HUGGINGFACE_API_KEY')
        }
        
        base_url_map = {
            'ollama': os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434')
        }
        
        config = LLMConfig(
            provider=provider,
            model=model_map.get(provider, 'gpt-4o'),
            temperature=0.0,
            max_tokens=2000,
            api_key=api_key_map.get(provider),
            base_url=base_url_map.get(provider)
        )
        
        return cls.PROVIDERS[provider](config)
    
    @classmethod
    def get_available_providers(cls) -> list:
        """Get list of available providers."""
        return list(cls.PROVIDERS.keys())


def get_llm_client(provider: Optional[str] = None) -> BaseLLMClient:
    """Get configured LLM client.
    
    Args:
        provider: Optional provider override
        
    Returns:
        LLM client instance
    """
    return LLMFactory.create(provider)
