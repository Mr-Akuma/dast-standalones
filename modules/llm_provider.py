"""
LLM Provider Abstraction Layer
==============================
Unified interface over multiple LLM backends:
  - Anthropic  (Claude Sonnet / Haiku)
  - OpenAI     (GPT-4o / GPT-4o-mini)
  - Ollama     (local models — llama3, mistral, codellama, etc.)

All backends expose the same `chat(messages)` signature.
Auto-selection order: anthropic → openai → ollama → RuntimeError.

Usage::

    from modules.llm_provider import LLMProvider

    provider = LLMProvider(api_keys={"anthropic": "sk-ant-..."})
    response = provider.chat([
        {"role": "system", "content": "You are a security researcher."},
        {"role": "user",   "content": "Generate SQLi payloads."},
    ])

Thread-safe: the provider itself holds no mutable state per-call.
"""
from __future__ import annotations

import json
import logging
import socket
import urllib.error
import urllib.request
from typing import Any

log = logging.getLogger("dast.llm_provider")

# ── Default model names per backend ──────────────────────────────────────────

_DEFAULT_MODELS: dict[str, str] = {
    "anthropic": "claude-sonnet-4-6",
    "openai":    "gpt-4o-mini",
    "ollama":    "llama3",
}

_DEFAULT_TIMEOUTS: dict[str, int] = {
    "anthropic": 45,
    "openai":    45,
    "ollama":    90,  # local models can be slow on first token
}


# ── Low-level HTTP helper (no external deps) ─────────────────────────────────

def _post_json(url: str, payload: dict, headers: dict, timeout: int) -> dict:
    """POST JSON payload and return parsed JSON response. Raises on error."""
    body = json.dumps(payload).encode()
    req  = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


# ══════════════════════════════════════════════════════════════════════════════
# Backend implementations
# ══════════════════════════════════════════════════════════════════════════════

class _AnthropicBackend:
    name = "anthropic"

    def __init__(self, api_key: str, model: str, timeout: int, max_tokens: int):
        self.api_key    = api_key
        self.model      = model
        self.timeout    = timeout
        self.max_tokens = max_tokens

    def chat(self, messages: list[dict]) -> str:
        system    = next((m["content"] for m in messages if m["role"] == "system"), "")
        user_msgs = [m for m in messages if m["role"] != "system"]
        resp = _post_json(
            "https://api.anthropic.com/v1/messages",
            {
                "model":      self.model,
                "max_tokens": self.max_tokens,
                "system":     system,
                "messages":   user_msgs,
            },
            {
                "Content-Type":      "application/json",
                "x-api-key":         self.api_key,
                "anthropic-version": "2023-06-01",
            },
            self.timeout,
        )
        return resp["content"][0]["text"].strip()


class _OpenAIBackend:
    name = "openai"

    def __init__(self, api_key: str, model: str, timeout: int, max_tokens: int):
        self.api_key    = api_key
        self.model      = model
        self.timeout    = timeout
        self.max_tokens = max_tokens

    def chat(self, messages: list[dict]) -> str:
        resp = _post_json(
            "https://api.openai.com/v1/chat/completions",
            {
                "model":       self.model,
                "messages":    messages,
                "temperature": 0.2,
                "max_tokens":  self.max_tokens,
            },
            {
                "Content-Type":  "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            self.timeout,
        )
        if not resp.get("choices"):
            raise RuntimeError(f"OpenAI: no choices in response: {resp}")
        return resp["choices"][0]["message"]["content"].strip()


class _OllamaBackend:
    name = "ollama"

    def __init__(self, host: str, model: str, timeout: int, max_tokens: int):
        self.host       = host.rstrip("/")
        self.model      = model
        self.timeout    = timeout
        self.max_tokens = max_tokens

    def chat(self, messages: list[dict]) -> str:
        # Ollama /api/chat endpoint — OpenAI-compatible messages format
        resp = _post_json(
            f"{self.host}/api/chat",
            {
                "model":    self.model,
                "messages": messages,
                "stream":   False,
                "options":  {"num_predict": self.max_tokens},
            },
            {"Content-Type": "application/json"},
            self.timeout,
        )
        return resp["message"]["content"].strip()

    @classmethod
    def is_reachable(cls, host: str) -> bool:
        """Check if Ollama is running at host."""
        try:
            parsed = urllib.request.urlparse(host) if hasattr(urllib.request, "urlparse") else None
            # Simple TCP probe
            from urllib.parse import urlparse as _up
            p = _up(host)
            s = socket.create_connection((p.hostname or "localhost", p.port or 11434), timeout=2)
            s.close()
            return True
        except Exception:
            return False


# ══════════════════════════════════════════════════════════════════════════════
# Public interface
# ══════════════════════════════════════════════════════════════════════════════

class LLMProvider:
    """Unified LLM interface. Auto-selects available backend.

    Priority: anthropic → openai → ollama.

    Args:
        api_keys:   dict with keys "anthropic", "openai" (string API keys).
        ollama_host: Ollama base URL (default: http://localhost:11434).
        models:     Override default model names, e.g. {"openai": "gpt-4o"}.
        timeouts:   Override default timeouts in seconds.
        max_tokens: Maximum tokens in LLM response (default: 2000).
        preferred:  Force a specific backend name ("anthropic"/"openai"/"ollama").
    """

    def __init__(
        self,
        api_keys:    dict[str, str] | None = None,
        ollama_host: str = "http://localhost:11434",
        models:      dict[str, str] | None = None,
        timeouts:    dict[str, int] | None = None,
        max_tokens:  int = 2000,
        preferred:   str | None = None,
    ):
        self._max_tokens = max_tokens
        keys      = api_keys or {}
        _models   = {**_DEFAULT_MODELS,   **(models   or {})}
        _timeouts = {**_DEFAULT_TIMEOUTS, **(timeouts or {})}

        self._backends: dict[str, Any] = {}

        if keys.get("anthropic"):
            self._backends["anthropic"] = _AnthropicBackend(
                keys["anthropic"], _models["anthropic"],
                _timeouts["anthropic"], max_tokens,
            )
        if keys.get("openai"):
            self._backends["openai"] = _OpenAIBackend(
                keys["openai"], _models["openai"],
                _timeouts["openai"], max_tokens,
            )
        if _OllamaBackend.is_reachable(ollama_host):
            self._backends["ollama"] = _OllamaBackend(
                ollama_host, _models["ollama"],
                _timeouts["ollama"], max_tokens,
            )

        # Select active backend
        priority = ["anthropic", "openai", "ollama"]
        if preferred and preferred in self._backends:
            self._active: str | None = preferred
        else:
            self._active = next((b for b in priority if b in self._backends), None)

    # ── Public API ────────────────────────────────────────────────────────────

    def chat(self, messages: list[dict]) -> str:
        """Send messages and return response text.

        Args:
            messages: List of {"role": "system"|"user"|"assistant", "content": str}

        Raises:
            RuntimeError: No backend is configured/reachable.
        """
        if not self._active:
            raise RuntimeError(
                "LLMProvider: no backend available. "
                "Set an API key (anthropic/openai) or run Ollama locally."
            )
        backend = self._backends[self._active]
        try:
            return backend.chat(messages)
        except Exception as exc:
            log.warning("[LLMProvider] %s failed: %s — trying next backend", self._active, exc)
            # Fallback to next available backend
            priority = ["anthropic", "openai", "ollama"]
            for name in priority:
                if name == self._active or name not in self._backends:
                    continue
                try:
                    return self._backends[name].chat(messages)
                except Exception as exc2:
                    log.warning("[LLMProvider] %s fallback failed: %s", name, exc2)
            raise RuntimeError(f"All LLM backends failed. Last error: {exc}") from exc

    def available_backends(self) -> list[str]:
        """Return list of configured and reachable backend names."""
        return list(self._backends.keys())

    def active_backend(self) -> str | None:
        """Return name of currently active backend, or None."""
        return self._active

    @property
    def is_available(self) -> bool:
        """True if at least one backend is configured."""
        return bool(self._active)

    def __repr__(self) -> str:
        return (
            f"LLMProvider(active={self._active!r}, "
            f"available={self.available_backends()})"
        )
