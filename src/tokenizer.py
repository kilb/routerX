"""Thin wrapper around tiktoken.

Caches per-model encodings. Falls back to ``cl100k_base`` when the requested
model has no registered encoding, and finally to ``len(text) // 4`` if
tiktoken itself is unavailable.
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("router-auditor.tokenizer")


class TokenCounter:
    def __init__(self):
        self._enc: dict[str, Any] = {}

    def count(self, text: str, model: str = "gpt-4o") -> int:
        enc = self._get(model)
        return len(enc.encode(text)) if enc else len(text) // 4

    def get_token_id(self, text: str, model: str = "gpt-4o") -> int | None:
        enc = self._get(model)
        if enc is None:
            return None
        ids = enc.encode(text)
        return ids[0] if len(ids) == 1 else None

    def find_single_token(
        self, candidates: list[str], model: str = "gpt-4o"
    ) -> tuple[str, int] | None:
        """Return the first candidate that encodes to exactly one token id."""
        enc = self._get(model)
        if enc is None:
            return None
        for w in candidates:
            ids = enc.encode(w)
            if len(ids) == 1:
                return w, ids[0]
        return None

    def tokenize(self, text: str, model: str = "gpt-4o") -> list[str]:
        enc = self._get(model)
        if enc is None:
            return list(text)
        return [enc.decode([t]) for t in enc.encode(text)]

    def is_exact_encoding(self, model: str) -> bool:
        """Return True if tiktoken has a model-specific encoding (not fallback)."""
        try:
            import tiktoken
            tiktoken.encoding_for_model(model)
            return True
        except (KeyError, Exception):
            return False

    def _get(self, model: str):
        if model in self._enc:
            return self._enc[model]
        enc = None
        try:
            import tiktoken

            try:
                enc = tiktoken.encoding_for_model(model)
            except KeyError:
                enc = tiktoken.get_encoding("cl100k_base")
        except Exception as e:  # tiktoken missing or load failed
            logger.warning("tiktoken unavailable for model %s: %s", model, e)
            enc = None
        self._enc[model] = enc
        return enc


token_counter = TokenCounter()
