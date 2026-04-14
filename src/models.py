"""Data models for Router Auditor.

All pydantic models are defined here. Enums cover priorities, verdicts,
judgement modes, provider types, capabilities, and authentication methods.
"""
from __future__ import annotations

import json as _json
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, model_validator


class Priority(str, Enum):
    PRE_SCREEN = "pre_screen"
    S0 = "S0"
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"


class Verdict(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    SUSPICIOUS = "suspicious"
    SKIP = "skip"
    INCONCLUSIVE = "inconclusive"


class JudgeMode(str, Enum):
    ONCE = "once"
    MAJORITY_2_OF_2 = "2/2"
    RELATIVE = "relative"


class ProviderType(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"
    ANY = "any"


class Capability(str, Enum):
    TEXT = "text"
    VISION = "vision"
    PDF = "pdf"
    AUDIO = "audio"
    TASK_MODEL = "task_model"
    TOOL_CALLING = "tool_calling"


class AuthMethod(str, Enum):
    BEARER = "bearer"
    X_API_KEY = "x-api-key"
    QUERY = "query"


class ApiFormat(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    AUTO = "auto"


class TaskModelConfig(BaseModel):
    create_endpoint: str = "/v1/tasks"
    poll_endpoint: str = "/v1/tasks/{task_id}"
    result_endpoint: str = "/v1/tasks/{task_id}/result"
    poll_interval_seconds: float = 2.0
    max_poll_attempts: int = 60
    task_id_field: str = "task_id"


class ProbeRequest(BaseModel):
    payload: dict[str, Any]
    description: str
    endpoint_path: str = "/chat/completions"


class ProbeResponse(BaseModel):
    status_code: int
    body: dict[str, Any] | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    raw_text: str = ""
    latency_ms: float = 0.0
    error: str | None = None
    chunks: list[dict[str, Any]] = Field(default_factory=list)
    chunk_timestamps: list[float] = Field(default_factory=list)

    @property
    def is_network_error(self) -> bool:
        return self.status_code == 0

    @property
    def content(self) -> str:
        """Extract text content across OpenAI / Anthropic / Gemini / stream formats.

        Anthropic responses may contain multiple content blocks (text + tool_use
        + thinking). Every block with ``type == "text"`` is concatenated so no
        text is dropped. For Gemini, all ``parts[*].text`` are joined for the
        same reason.
        """
        if self.body is None:
            return ""
        # OpenAI
        try:
            v = self.body["choices"][0]["message"]["content"]
            if v is not None and v != "":
                return str(v)
        except (KeyError, IndexError, TypeError):
            pass
        # Anthropic: aggregate every text block.
        try:
            blocks = self.body["content"]
            if isinstance(blocks, list):
                texts = [
                    b.get("text", "") for b in blocks
                    if isinstance(b, dict) and b.get("type") == "text"
                ]
                joined = "".join(texts)
                if joined:
                    return joined
        except (KeyError, TypeError):
            pass
        # Gemini: aggregate every part.
        try:
            parts = self.body["candidates"][0]["content"]["parts"]
            if isinstance(parts, list):
                texts = [p.get("text", "") for p in parts if isinstance(p, dict)]
                joined = "".join(texts)
                if joined:
                    return joined
        except (KeyError, IndexError, TypeError):
            pass
        # Stream body (assembled by RouterClient.send_stream).
        v = self.body.get("full_content")
        if v is not None and v != "":
            return str(v)
        return ""

    @property
    def finish_reason(self) -> str | None:
        if self.body is None:
            return None
        try:
            return self.body["choices"][0]["finish_reason"]
        except (KeyError, IndexError, TypeError):
            pass
        try:
            return self.body["stop_reason"]
        except (KeyError, TypeError):
            pass
        # Stream body: top-level finish_reason set by send_stream().
        return self.body.get("finish_reason")

    @property
    def tool_calls(self) -> list[dict[str, Any]]:
        """Return tool calls in a provider-neutral shape.

        Each returned dict carries ``id``, ``type="function"``, and a
        ``function`` subdict with ``name`` and ``arguments`` (JSON-string,
        matching OpenAI convention). Anthropic ``tool_use`` blocks are
        normalised accordingly.
        """
        if self.body is None:
            return []
        # OpenAI
        try:
            calls = self.body["choices"][0]["message"].get("tool_calls")
            if calls:
                return list(calls)
        except (KeyError, IndexError, TypeError):
            pass
        # Anthropic: tool_use blocks inside content[].
        try:
            blocks = self.body.get("content")
            if isinstance(blocks, list):
                normalised: list[dict[str, Any]] = []
                for b in blocks:
                    if isinstance(b, dict) and b.get("type") == "tool_use":
                        normalised.append({
                            "id": b.get("id", ""),
                            "type": "function",
                            "function": {
                                "name": b.get("name", ""),
                                "arguments": _json.dumps(b.get("input", {})),
                            },
                        })
                if normalised:
                    return normalised
        except (KeyError, TypeError):
            pass
        return []

    @property
    def usage(self) -> dict[str, Any] | None:
        if self.body is None:
            return None
        return self.body.get("usage")


class DetectorResult(BaseModel):
    detector_id: str
    detector_name: str
    priority: Priority
    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: dict[str, Any] = Field(default_factory=dict)
    sub_probes: list[dict[str, Any]] = Field(default_factory=list)
    latency_ms: float = 0.0
    request_count: int = 0
    skipped_reason: str | None = None


class TestConfig(BaseModel):
    # Required
    router_endpoint: str
    api_key: str

    # Identity claims
    claimed_model: str = "gpt-4o"
    claimed_provider: ProviderType = ProviderType.ANY
    claimed_single_route: bool = False

    # Capability claims
    capabilities: list[Capability] = Field(
        default_factory=lambda: [Capability.TEXT]
    )

    # Authentication
    auth_method: AuthMethod = AuthMethod.BEARER
    api_format: ApiFormat = ApiFormat.OPENAI
    extra_headers: dict[str, str] = Field(default_factory=dict)

    # Direct provider (optional baseline)
    direct_endpoint: str | None = None
    direct_api_key: str | None = None
    direct_auth_method: AuthMethod | None = None

    # Async task model (D55)
    task_model_config: TaskModelConfig | None = None

    # Runtime parameters
    timeout: float = 30.0
    max_concurrent: int = 5
    min_request_interval: float = 0.1

    @model_validator(mode="after")
    def validate_config(self):
        conflicts = {
            ProviderType.OPENAI: ["claude-", "gemini-"],
            ProviderType.ANTHROPIC: ["gpt-", "gemini-", "o1-", "o3-"],
            ProviderType.GEMINI: ["gpt-", "claude-", "o1-", "o3-"],
        }
        if self.claimed_provider in conflicts:
            for prefix in conflicts[self.claimed_provider]:
                if self.claimed_model.lower().startswith(prefix):
                    raise ValueError(
                        f"model '{self.claimed_model}' conflicts with "
                        f"provider '{self.claimed_provider.value}'"
                    )
        if (Capability.TASK_MODEL in self.capabilities
                and self.task_model_config is None):
            self.task_model_config = TaskModelConfig()
        if self.api_format == ApiFormat.AUTO:
            if self.claimed_provider == ProviderType.ANTHROPIC:
                self.api_format = ApiFormat.ANTHROPIC
            else:
                self.api_format = ApiFormat.OPENAI
        if self.direct_endpoint and self.direct_auth_method is None:
            self.direct_auth_method = self.auth_method
        return self

    @property
    def default_endpoint_path(self) -> str:
        if self.api_format == ApiFormat.ANTHROPIC:
            return "/v1/messages"
        return "/chat/completions"


class TestReport(BaseModel):
    router_endpoint: str
    test_timestamp: str
    overall_verdict: Verdict
    tier_assignment: str
    total_detectors: int
    passed: int
    failed: int
    suspicious: int
    skipped: int
    total_requests: int
    total_latency_ms: float
    estimated_cost_usd: float
    results: list[DetectorResult]
    evidence_notes: list[str] = Field(default_factory=list)
