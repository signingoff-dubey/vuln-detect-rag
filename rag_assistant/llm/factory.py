"""LLM client module: factory."""

import os
import time
import logging
from typing import Optional, Dict, List, Tuple
from .remote_clients import GeminiClient, GroqClient, HuggingFaceClient, NvidiaClient, OpenRouterClient
from .base import BaseLLMClient, LLMConfig
from .openai_client import OpenAIClient
from .ollama_client import OllamaClient

logger = logging.getLogger(__name__)


class LLMFactory:
    """Factory for creating LLM clients."""

    #: Local models known to handle instruction-following and tool calling
    #: well, best first. Used when auto-selecting a model.
    PREFERRED_OLLAMA_MODELS = (
        'qwen3-coder',
        'qwen2.5-coder',
        'qwen3',
        'qwen2.5',
        'llama3.3',
        'llama3.1',
        'llama3.2',
        'mistral-nemo',
        'mistral',
        'gemma3',
        'phi4',
    )

    #: Models that cannot serve as the chat backend. Vision/embedding models
    #: appear in `ollama list` alongside chat models, and picking one silently
    #: produces useless answers rather than a clear error.
    UNSUITABLE_MODEL_MARKERS = (
        'embed',        # nomic-embed-text, mxbai-embed-large, ...
        'llava',        # vision
        'moondream',    # vision
        'bakllava',     # vision
        'clip',
        'minilm',
        'rerank',
        'whisper',      # speech
    )

    @staticmethod
    def check_ollama_available(refresh: bool = False) -> dict:
        """Check if Ollama is running and detect available models.

        Talks to the HTTP API rather than shelling out to ``ollama list``, so it
        also works when the daemon is remote or the CLI is not on PATH.

        The result is cached, because this is called several times while
        serving a single page: ``/api/providers`` calls it directly and again
        inside the provider loop, and ``is_configured('ollama')`` calls it once
        more. Uncached, with Ollama not running, each of those waited on its
        own connection failure and the dashboard spent tens of seconds probing
        a daemon that was already known to be down.

        Failures are cached for longer than successes. A refused connection is
        a stable fact for as long as nobody starts the daemon, whereas an
        available daemon can gain or lose models, so the two deserve different
        TTLs. Pass ``refresh=True`` to force a probe -- the UI's explicit
        "recheck" path should, since the user is asking precisely because they
        just started Ollama.
        """
        cached = _OLLAMA_STATUS_CACHE.get("entry")
        if cached and not refresh:
            fetched_at, value = cached
            ttl = (_OLLAMA_UP_TTL_SECONDS if value.get("available")
                   else _OLLAMA_DOWN_TTL_SECONDS)
            if (time.time() - fetched_at) < ttl:
                # A copy, so a caller mutating the dict cannot poison the cache.
                return dict(value, models=list(value.get("models", [])))

        result = {
            "available": False,
            "model": "",
            "provider": "ollama",
            "models": [],
            "base_url": os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434'),
            "supports_tools": False,
            "error": "",
        }
        try:
            # Plain HTTP against /api/tags rather than the `ollama` package or
            # the CLI: this reports accurately even when the Python package is
            # missing or the daemon is remote, which both of those miss.
            import requests

            # Separate connect and read timeouts. The old single 10s value
            # applied to the connect phase too, so an unreachable daemon held
            # the request open far longer than establishing a local TCP
            # connection could ever legitimately need.
            #
            # Retries are disabled outright. urllib3 retries a refused
            # connection by default, and because "localhost" resolves to both
            # ::1 and 127.0.0.1 on Windows the connect timeout is already paid
            # once per address; retrying multiplies that again.
            from requests.adapters import HTTPAdapter

            session = requests.Session()
            session.mount("http://", HTTPAdapter(max_retries=0))
            session.mount("https://", HTTPAdapter(max_retries=0))
            with session:
                response = session.get(
                    f"{result['base_url']}/api/tags",
                    timeout=(_OLLAMA_CONNECT_TIMEOUT, _OLLAMA_READ_TIMEOUT),
                )
            response.raise_for_status()
            listing = response.json()

            for entry in listing.get('models', []):
                name = entry.get('model') or entry.get('name')
                if name:
                    result["models"].append(name)

            if not result["models"]:
                result["error"] = (
                    "Ollama is running but has no models installed. "
                    "Run: ollama pull qwen2.5-coder:7b"
                )
                return _cache_ollama_status(result)

            configured = os.getenv('OLLAMA_MODEL')
            if configured and configured in result["models"]:
                result["model"] = configured
            else:
                result["model"] = LLMFactory._pick_best_model(result["models"])
                if configured:
                    result["error"] = (
                        f"Configured model '{configured}' is not installed; "
                        f"falling back to '{result['model']}'."
                    )

            result["available"] = True
            result["supports_tools"] = any(
                pref in result["model"]
                for pref in LLMFactory.PREFERRED_OLLAMA_MODELS
            )

        except ImportError:
            result["error"] = "The 'requests' package is not installed."
        except Exception as e:
            result["error"] = (
                f"Cannot reach Ollama at {result['base_url']}: {e}. "
                f"Start it with: ollama serve"
            )
            logger.debug("Ollama unavailable at %s: %s", result['base_url'], e)

        return _cache_ollama_status(result)

    @staticmethod
    def is_cloud_model(model: str) -> bool:
        """Whether a model tag routes to Ollama Cloud instead of local hardware.

        Ollama lists cloud-hosted models next to local ones. Running one sends
        the prompt — including scan findings — off the machine, which would
        silently break this project's privacy-first guarantee, so they are
        never auto-selected.

        Cloud tags take several shapes (``model:cloud``, ``qwen3-coder:480b-cloud``),
        so the whole tag is inspected rather than matching one exact suffix.
        """
        lowered = (model or "").lower()
        tag = lowered.split(':', 1)[1] if ':' in lowered else ''
        return lowered.endswith(':cloud') or 'cloud' in tag

    @staticmethod
    def is_chat_capable(model: str) -> bool:
        """Whether a model can plausibly serve as the chat backend."""
        lowered = model.lower()
        return not any(
            marker in lowered for marker in LLMFactory.UNSUITABLE_MODEL_MARKERS
        )

    @staticmethod
    def _pick_best_model(models: List[str]) -> str:
        """Prefer a known local instruct model over an arbitrary one.

        Blindly taking ``models[0]`` selects whatever sorts first — commonly an
        embedding model (nomic-embed-text) or a vision model (llava), neither
        of which can answer a question. Cloud-routed models are excluded so
        auto-selection can never silently leave the machine.
        """
        local_chat = [
            m for m in models
            if LLMFactory.is_chat_capable(m) and not LLMFactory.is_cloud_model(m)
        ]
        # Degrade deliberately: local chat > any local > any chat > anything.
        pool = (
            local_chat
            or [m for m in models if not LLMFactory.is_cloud_model(m)]
            or [m for m in models if LLMFactory.is_chat_capable(m)]
            or models
        )

        for preferred in LLMFactory.PREFERRED_OLLAMA_MODELS:
            for model in pool:
                if preferred in model.lower():
                    return model
        return pool[0]

    PROVIDERS = {
        'openai': OpenAIClient,
        'ollama': OllamaClient,
        'groq': GroqClient,
        'gemini': GeminiClient,
        'openrouter': OpenRouterClient,
        'nvidia': NvidiaClient,
        'huggingface': HuggingFaceClient
    }

    #: Providers tried in order when LLM_PROVIDER is unset or "auto".
    #: Cloud providers lead because they need no local model download and no
    #: GPU; Ollama trails as the offline fallback. Override with
    #: LLM_PROVIDER_ORDER, e.g. "ollama,gemini" to prioritise local inference.
    DEFAULT_PROVIDER_ORDER = ('groq', 'gemini', 'openrouter', 'nvidia', 'ollama')

    @classmethod
    def disabled_providers(cls) -> set:
        """Providers switched off at runtime.

        Backed by an environment variable so it works for the API, the eval
        script, and a bare Python session alike. Being able to disable a
        provider is what makes per-provider comparison possible: an ablation
        that cannot isolate one backend cannot attribute a result to it.
        """
        raw = os.getenv('LLM_DISABLED_PROVIDERS', '')
        return {p.strip().lower() for p in raw.split(',') if p.strip()}

    @classmethod
    def set_provider_enabled(cls, provider: str, enabled: bool) -> set:
        """Turn a provider on or off for subsequent requests.

        Returns the updated set of disabled providers.
        """
        provider = provider.lower()
        if provider not in cls.PROVIDERS:
            raise ValueError(f"Unknown provider: {provider}")

        disabled = cls.disabled_providers()
        if enabled:
            disabled.discard(provider)
        else:
            disabled.add(provider)

        os.environ['LLM_DISABLED_PROVIDERS'] = ','.join(sorted(disabled))
        # Catalogues are per-provider and cheap to rebuild; clearing avoids
        # serving a stale list for a provider that was just re-enabled.
        _MODEL_CATALOGUE_CACHE.pop(provider, None)
        logger.info("Provider '%s' %s", provider, "enabled" if enabled else "disabled")
        return disabled

    @classmethod
    def provider_order(cls) -> List[str]:
        """Resolve the provider preference list, minus anything disabled."""
        configured = os.getenv('LLM_PROVIDER_ORDER', '')
        if configured:
            order = [p.strip().lower() for p in configured.split(',') if p.strip()]
        else:
            order = list(cls.DEFAULT_PROVIDER_ORDER)

        disabled = cls.disabled_providers()
        return [p for p in order if p in cls.PROVIDERS and p not in disabled]

    @classmethod
    def is_configured(cls, provider: str) -> bool:
        """Whether a provider has what it needs to actually answer a request.

        Checked before selection so an unusable provider is skipped up front
        rather than failing on the user's first question.
        """
        provider = provider.lower()
        if provider in cls.disabled_providers():
            return False
        if provider == 'ollama':
            return cls.check_ollama_available()["available"]
        key_env = {
            'openai': 'OPENAI_API_KEY',
            'groq': 'GROQ_API_KEY',
            'gemini': 'GEMINI_API_KEY',
            'openrouter': 'OPENROUTER_API_KEY',
            'nvidia': 'NVIDIA_API_KEY',
            'huggingface': 'HUGGINGFACE_API_KEY',
        }.get(provider)
        return bool(key_env and os.getenv(key_env))

    @classmethod
    def resolve_provider(cls, provider: Optional[str] = None) -> str:
        """Pick which provider to use.

        An explicit choice is honoured even if it looks unconfigured, so the
        user gets a precise error rather than a silent substitution. Only
        "auto" (or an unset LLM_PROVIDER) walks the preference list.
        """
        requested = (provider or os.getenv('LLM_PROVIDER', 'auto')).lower()

        if requested and requested != 'auto':
            if requested not in cls.PROVIDERS:
                raise ValueError(
                    f"Unknown LLM provider: {requested}. "
                    f"Valid options: {', '.join(cls.PROVIDERS)}, auto"
                )
            return requested

        for candidate in cls.provider_order():
            if cls.is_configured(candidate):
                logger.info("Auto-selected LLM provider: %s", candidate)
                return candidate

        logger.warning(
            "No LLM provider is configured. Set GROQ_API_KEY or GEMINI_API_KEY, "
            "or install a local model with 'ollama pull qwen2.5-coder:7b'."
        )
        return cls.provider_order()[0] if cls.provider_order() else 'ollama'

    @classmethod
    def create(cls, provider: Optional[str] = None) -> BaseLLMClient:
        """Create LLM client based on configuration.

        Args:
            provider: LLM provider name

        Returns:
            LLM client instance
        """
        provider = cls.resolve_provider(provider)

        if provider == 'ollama':
            ollama_status = cls.check_ollama_available()
            default_ollama_model = (
                ollama_status["model"] if ollama_status["available"]
                else 'qwen2.5-coder:7b'
            )
        else:
            default_ollama_model = 'qwen2.5-coder:7b'

        model_map = {
            'openai': os.getenv('OPENAI_MODEL', 'gpt-4o'),
            'ollama': os.getenv('OLLAMA_MODEL', default_ollama_model),
            # llama-3.1-70b-versatile was decommissioned by Groq; 3.3 is the
            # current general-purpose model on that endpoint.
            'groq': os.getenv('GROQ_MODEL', 'openai/gpt-oss-120b'),
            # gemini-2.0-flash is on the free tier and fast enough for chat.
            'gemini': os.getenv('GEMINI_MODEL', 'gemini-flash-latest'),
            # Free tier only; the client refuses any model that costs money.
            'openrouter': os.getenv('OPENROUTER_MODEL', 'openrouter/free'),
            'nvidia': os.getenv('NVIDIA_MODEL', 'nvidia/nemotron-3-super-120b-a12b'),
            'huggingface': os.getenv('HUGGINGFACE_MODEL', 'meta-llama/Llama-3.1-8B-Instruct')
        }

        # If the configured Ollama model is not actually installed, fall back to
        # one that is, rather than failing every request at generation time.
        model = model_map.get(provider, 'gpt-4o')
        if provider == 'ollama':
            status = cls.check_ollama_available()
            if status["available"] and model not in status["models"]:
                logger.warning("Ollama model '%s' not installed; using '%s'",
                               model, status["model"])
                model = status["model"]

        api_key_map = {
            'openai': os.getenv('OPENAI_API_KEY'),
            'groq': os.getenv('GROQ_API_KEY'),
            # GOOGLE_API_KEY is accepted too, matching Google's own tooling.
            'gemini': os.getenv('GEMINI_API_KEY') or os.getenv('GOOGLE_API_KEY'),
            'openrouter': os.getenv('OPENROUTER_API_KEY'),
            'nvidia': os.getenv('NVIDIA_API_KEY'),
            'huggingface': os.getenv('HUGGINGFACE_API_KEY')
        }

        base_url_map = {
            'ollama': os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434')
        }

        if provider != 'ollama' and not api_key_map.get(provider):
            logger.warning(
                "%s selected but no API key is set (%s_API_KEY). "
                "Requests will fail; set the key or use LLM_PROVIDER=auto.",
                provider, provider.upper(),
            )

        config = LLMConfig(
            provider=provider,
            model=model,
            temperature=float(os.getenv('LLM_TEMPERATURE', '0.1')),
            max_tokens=int(os.getenv('LLM_MAX_TOKENS', '2000')),
            api_key=api_key_map.get(provider),
            base_url=base_url_map.get(provider),
            context_window=int(os.getenv('LLM_CONTEXT_WINDOW', '8192')),
            request_timeout=int(os.getenv('LLM_TIMEOUT', '180')),
        )

        return cls.PROVIDERS[provider](config)

    @classmethod
    def get_available_providers(cls) -> list:
        """Get list of available providers."""
        return list(cls.PROVIDERS.keys())

    @classmethod
    def list_models(cls, provider: str, refresh: bool = False) -> List[str]:
        """Every chat-capable model a provider currently offers, best first.

        Cached briefly: rotation consults this on failure, and re-querying the
        catalogue on every request would add a round trip to each answer.
        """
        provider = provider.lower()
        cached = _MODEL_CATALOGUE_CACHE.get(provider)
        if cached and not refresh and (time.time() - cached[0]) < _CATALOGUE_TTL_SECONDS:
            return cached[1]

        models: List[str] = []
        try:
            if provider == 'ollama':
                status = cls.check_ollama_available()
                models = [
                    m for m in status.get('models', [])
                    if cls.is_chat_capable(m) and not cls.is_cloud_model(m)
                ]
                models.sort(key=lambda m: cls._preference_rank(
                    m, cls.PREFERRED_OLLAMA_MODELS))
            elif provider in ('groq', 'gemini', 'openrouter', 'nvidia'):
                client = cls.create(provider)
                models = [
                    m for m in client._list_remote_models()
                    if client._is_chat_model(m)
                ]
                models.sort(key=lambda m: cls._preference_rank(
                    m, client.PREFERRED_MODELS))
        except Exception as e:
            logger.warning("Could not list %s models: %s", provider, e)

        if models:
            _MODEL_CATALOGUE_CACHE[provider] = (time.time(), models)
        return models

    @staticmethod
    def _preference_rank(model: str, preferred: Tuple[str, ...]) -> int:
        """Sort key placing preferred models first, unknown ones last."""
        lowered = model.lower()
        for index, name in enumerate(preferred):
            if name in lowered:
                return index
        return len(preferred)


#: Cache of live model catalogues, so rotation does not re-query the provider
#: on every request. (provider -> (fetched_at, [model_ids]))
_MODEL_CATALOGUE_CACHE: Dict[str, Tuple[float, List[str]]] = {}
_CATALOGUE_TTL_SECONDS = 900

#: Cache of the last Ollama probe. ("entry" -> (fetched_at, status_dict))
#: A single-key dict rather than a bare global so the value can be replaced
#: atomically from any thread without a lock: dict item assignment is one
#: bytecode, and a reader either sees the old tuple or the new one.
_OLLAMA_STATUS_CACHE: Dict[str, Tuple[float, dict]] = {}

#: An available daemon can gain or lose models between calls, so its status is
#: held only briefly. A refused connection stays refused until someone starts
#: the daemon, so it is held longer -- that is the case that was costing whole
#: seconds per request.
_OLLAMA_UP_TTL_SECONDS = 30
_OLLAMA_DOWN_TTL_SECONDS = 120

#: Connecting to a daemon on localhost either succeeds immediately or is
#: refused immediately; anything slower is a daemon that is not there. Kept low
#: because "localhost" resolves to both ::1 and 127.0.0.1 on Windows and the
#: connect timeout is paid once per address, so the wall-clock cost of a cold
#: probe against a stopped daemon is roughly twice this value. The read timeout
#: is separate and more generous, since listing many models is real work.
_OLLAMA_CONNECT_TIMEOUT = 0.6
_OLLAMA_READ_TIMEOUT = 8.0


def _cache_ollama_status(result: dict) -> dict:
    """Store an Ollama probe result and return it.

    Logging happens here rather than at the call site so it fires on a change
    of state instead of once per probe. The old code logged a warning every
    time the check ran, which -- called several times per page load against a
    daemon that was not running -- produced pages of identical stack traces
    that buried anything worth reading.
    """
    previous = _OLLAMA_STATUS_CACHE.get("entry")
    was_available = previous[1].get("available") if previous else None
    now_available = bool(result.get("available"))

    if was_available != now_available:
        if now_available:
            logger.info("Ollama available at %s (model '%s')",
                        result.get("base_url"), result.get("model"))
        elif result.get("error"):
            logger.warning("Ollama unavailable: %s", result["error"])

    _OLLAMA_STATUS_CACHE["entry"] = (time.time(), result)
    return result
