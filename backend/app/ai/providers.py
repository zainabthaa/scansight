"""Provider-agnostic LLM access.

Every provider implements the same tiny interface: `complete(system, user) -> str`.
Adding a new provider means writing one class; the explainer never changes.
HTTP calls are made with httpx directly, so no vendor SDKs are required.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

import httpx

from app.config import Settings

DEFAULT_MODELS = {
    "anthropic": "claude-haiku-5-5",
    "openai": "gpt-4o-mini",
    "ollama": "llama3.1:8b",
}


class ProviderError(RuntimeError):
    pass


class LLMProvider(ABC):
    name: str

    def __init__(self, model: str, timeout: float = 60.0):
        self.model = model
        self.timeout = timeout

    @abstractmethod
    async def complete(self, system: str, user: str) -> str: ...

    async def _post(self, url: str, json: dict, headers: dict | None = None) -> dict:
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(url, json=json, headers=headers or {})
        except httpx.HTTPError as exc:
            raise ProviderError(f"{self.name} request failed: {exc}") from exc
        if resp.status_code >= 400:
            raise ProviderError(f"{self.name} returned HTTP {resp.status_code}: {resp.text[:300]}")
        return resp.json()


class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def __init__(self, api_key: str, model: str):
        super().__init__(model)
        self.api_key = api_key

    async def complete(self, system: str, user: str) -> str:
        data = await self._post(
            "https://api.anthropic.com/v1/messages",
            json={
                "model": self.model,
                "max_tokens": 1200,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            },
            headers={"x-api-key": self.api_key, "anthropic-version": "2023-06-01"},
        )
        blocks = data.get("content", [])
        return "".join(b.get("text", "") for b in blocks if b.get("type") == "text")


class OpenAIProvider(LLMProvider):
    """Also works with any OpenAI-compatible API (set OPENAI_BASE_URL)."""

    name = "openai"

    def __init__(self, api_key: str, model: str, base_url: str):
        super().__init__(model)
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")

    async def complete(self, system: str, user: str) -> str:
        data = await self._post(
            f"{self.base_url}/chat/completions",
            json={
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "response_format": {"type": "json_object"},
            },
            headers={"Authorization": f"Bearer {self.api_key}"},
        )
        return data["choices"][0]["message"]["content"]


class OllamaProvider(LLMProvider):
    """Local models via Ollama: free, private, no API key."""

    name = "ollama"

    def __init__(self, base_url: str, model: str):
        super().__init__(model, timeout=180.0)  # local models can be slow on CPU
        self.base_url = base_url.rstrip("/")

    async def complete(self, system: str, user: str) -> str:
        data = await self._post(
            f"{self.base_url}/api/chat",
            json={
                "model": self.model,
                "stream": False,
                "format": "json",
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
        )
        return data.get("message", {}).get("content", "")


def build_provider(settings: Settings) -> LLMProvider | None:
    """Create the configured provider, or None when AI is disabled or misconfigured."""
    provider = settings.ai_provider
    if provider == "none":
        return None
    model = settings.ai_model or DEFAULT_MODELS[provider]
    if provider == "anthropic" and settings.anthropic_api_key:
        return AnthropicProvider(settings.anthropic_api_key, model)
    if provider == "openai" and settings.openai_api_key:
        return OpenAIProvider(settings.openai_api_key, model, settings.openai_base_url)
    if provider == "ollama":
        return OllamaProvider(settings.ollama_url, model)
    return None
