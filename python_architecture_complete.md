# Router Auditor — Python 架构设计（完整自包含版）

## 一、设计原则

1. **判定与 I/O 分离**：`send_probes()` 发请求，`judge()` 纯函数判定，可独立测试
2. **每个 Detector < 200 行**
3. **@detector 装饰器 + pkgutil 自动扫描注册**
4. **条件执行声明式**：类变量声明前提，Runner 统一 skip
5. **错误不崩溃**：网络错误 → ProbeResponse.error → judge() 判定
6. **shared_context**：Runner 维护跨 Detector 数据共享
7. **阶段内可并行**：无依赖的 Detector 用 asyncio.gather
8. **零人工数据**：全部测试素材纯算法生成
9. **多认证/多格式**：Bearer / x-api-key / query + OpenAI / Anthropic 格式
10. **EventBus 钩子**：松耦合事件系统

---

## 二、依赖清单

```toml
[project]
name = "router-auditor"
version = "0.1.0"
requires-python = ">=3.11"

dependencies = [
    "httpx>=0.27",
    "httpx-sse>=0.4",
    "pydantic>=2.0",
    "tiktoken>=0.7",
    "Pillow>=10.0",
    "pymupdf>=1.24.2",       # import pymupdf（非 import fitz）
    "rich>=13.0",
    "fastapi>=0.110",
]

[project.optional-dependencies]
serve = [
    "granian>=1.6; sys_platform != 'win32'",
    "uvicorn>=0.29",
]
dev = [
    "pytest>=8.0",
    "pytest-asyncio>=0.23",
    "uvicorn>=0.29",
]
```

---

## 三、项目结构

```
router-auditor/
├── pyproject.toml
├── src/
│   ├── __init__.py
│   ├── models.py              # 数据模型
│   ├── client.py              # HTTP 客户端（POST/GET/SSE + 多认证 + 速率控制 + 429 重试）
│   ├── tokenizer.py           # tiktoken 封装
│   ├── assets.py              # 测试素材纯算法生成（图片/PDF/音频）+ 内存缓存
│   ├── config.py              # 常量 + 指纹库
│   ├── registry.py            # BaseDetector 基类 + @detector 装饰器
│   ├── runner.py              # 阶段编排 + shared_context + 并行 + Ctrl+C
│   ├── reporter.py            # CLI 表格 + JUnit XML
│   ├── events.py              # EventBus 钩子系统
│   │
│   ├── detectors/
│   │   ├── __init__.py        # pkgutil 自动扫描
│   │   ├── d31_god_payload.py
│   │   ├── d28_session_crosstalk.py
│   │   ├── d47_address_consistency.py
│   │   ├── d48_amount_precision.py
│   │   ├── d45_toolcall_arg_verifier.py
│   │   ├── d21_physical_param.py
│   │   ├── d22_protocol_strictness.py
│   │   ├── d22e_cross_protocol.py
│   │   ├── d23_hijacked_token.py
│   │   ├── d30_error_path_forensics.py
│   │   ├── d50_semantic_negation.py
│   │   ├── d04a_tokenizer_fingerprint.py
│   │   ├── d04b_negative_constraint.py
│   │   ├── d16b_tool_calling.py
│   │   ├── d24a_context_truncation_canary.py
│   │   ├── d24b_context_truncation_algebra.py
│   │   ├── d25_output_cap.py
│   │   ├── d29_usage_bill_audit.py
│   │   ├── d26_semantic_cache.py
│   │   ├── d38_seed_reproducibility.py
│   │   ├── d54_task_completion.py
│   │   ├── d27_image_fidelity.py
│   │   ├── d27b_pdf_fidelity.py
│   │   ├── d27c_multi_image_order.py
│   │   ├── d27d_audio_fidelity.py
│   │   ├── d32a_streaming_basic.py
│   │   ├── d55_async_task.py
│   │   ├── d15_guardrail_integrity.py
│   │   ├── d37_stop_seq.py
│   │   ├── d11_request_integrity.py
│   │   └── d53_metadata_completeness.py
│   │
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── nonce.py
│   │   ├── eth.py
│   │   ├── text_analysis.py
│   │   └── timing.py
│   │
│   └── api/
│       ├── __init__.py
│       ├── app.py
│       ├── routes.py
│       ├── schemas.py
│       ├── task_manager.py
│       └── auth.py
│
├── tests/
│   ├── conftest.py
│   ├── mock_server.py
│   └── test_detectors/
│
└── scripts/
    ├── admission_test.py      # CLI 入口
    ├── serve.py               # API 服务入口
    └── self_test_all.py       # 批量自测
```

---

## 四、models.py

```python
from __future__ import annotations
from enum import Enum
from pydantic import BaseModel, Field, model_validator
from typing import Any


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
    task_id_field: str = "task_id"  # 从 create 响应中提取 ID 的字段名


class ProbeRequest(BaseModel):
    payload: dict[str, Any]
    description: str
    expect_error: bool = False
    endpoint_path: str = "/chat/completions"
    method: str = "POST"


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
        if self.body is None:
            return ""
        # OpenAI
        try:
            v = self.body["choices"][0]["message"]["content"]
            if v: return v
        except (KeyError, IndexError, TypeError): pass
        # Anthropic
        try:
            v = self.body["content"][0]["text"]
            if v: return v
        except (KeyError, IndexError, TypeError): pass
        # Gemini
        try:
            v = self.body["candidates"][0]["content"]["parts"][0]["text"]
            if v: return v
        except (KeyError, IndexError, TypeError): pass
        return ""

    @property
    def finish_reason(self) -> str | None:
        if self.body is None:
            return None
        try: return self.body["choices"][0]["finish_reason"]
        except (KeyError, IndexError, TypeError): pass
        try: return self.body["stop_reason"]
        except (KeyError, TypeError): pass
        return None

    @property
    def tool_calls(self) -> list[dict[str, Any]]:
        if self.body is None:
            return []
        try:
            return self.body["choices"][0]["message"].get("tool_calls", [])
        except (KeyError, IndexError, TypeError):
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
    # 必填
    router_endpoint: str
    api_key: str

    # 身份声明
    claimed_model: str = "gpt-4o"
    claimed_provider: ProviderType = ProviderType.ANY
    claimed_single_route: bool = False

    # 能力声明
    capabilities: list[Capability] = Field(
        default_factory=lambda: [Capability.TEXT]
    )

    # 认证
    auth_method: AuthMethod = AuthMethod.BEARER
    api_format: ApiFormat = ApiFormat.OPENAI
    extra_headers: dict[str, str] = Field(default_factory=dict)

    # 直连 Provider
    direct_endpoint: str | None = None
    direct_api_key: str | None = None
    direct_auth_method: AuthMethod | None = None

    # 异步任务模型
    task_model_config: TaskModelConfig | None = None

    # 运行参数
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
```

---

## 五、client.py

```python
from __future__ import annotations
import asyncio
import json
import time
import logging
import uuid
import httpx
from httpx_sse import aconnect_sse
from .models import ProbeRequest, ProbeResponse, AuthMethod

logger = logging.getLogger("router-auditor.client")


class RouterClient:
    def __init__(
        self,
        endpoint: str,
        api_key: str,
        auth_method: AuthMethod = AuthMethod.BEARER,
        extra_headers: dict[str, str] | None = None,
        timeout: float = 30.0,
        max_concurrent: int = 5,
        min_interval: float = 0.1,
    ):
        self.endpoint = endpoint.rstrip("/")
        self.api_key = api_key
        self.auth_method = auth_method
        self.extra_headers = extra_headers or {}
        self.timeout = timeout
        self._client: httpx.AsyncClient | None = None
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._min_interval = min_interval
        self._last_request_time = 0.0
        self._lock = asyncio.Lock()
        self._run_id = str(uuid.uuid4())[:8]

    async def __aenter__(self):
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout, connect=10.0),
            follow_redirects=True,
        )
        return self

    async def __aexit__(self, *args):
        if self._client:
            await self._client.aclose()

    def _headers(self, probe_id: str = "") -> dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self.auth_method == AuthMethod.BEARER:
            h["Authorization"] = f"Bearer {self.api_key}"
        elif self.auth_method == AuthMethod.X_API_KEY:
            h["x-api-key"] = self.api_key
            h["anthropic-version"] = "2023-06-01"
        cid = f"{self._run_id}-{probe_id}" if probe_id else self._run_id
        h["X-Correlation-ID"] = cid
        h["X-Test-Run-ID"] = self._run_id
        h.update(self.extra_headers)
        return h

    def _url(self, path: str) -> str:
        return f"{self.endpoint}{path}"

    def _query_params(self) -> dict[str, str] | None:
        if self.auth_method == AuthMethod.QUERY:
            return {"api_key": self.api_key}
        return None

    async def _throttle(self):
        async with self._lock:
            now = time.perf_counter()
            wait = self._min_interval - (now - self._last_request_time)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request_time = time.perf_counter()

    async def send(self, probe: ProbeRequest) -> ProbeResponse:
        max_retries = 2
        probe_id = str(uuid.uuid4())[:8]
        for attempt in range(max_retries + 1):
            async with self._semaphore:
                await self._throttle()
                t0 = time.perf_counter()
                try:
                    resp = await self._client.post(
                        self._url(probe.endpoint_path),
                        json=probe.payload,
                        headers=self._headers(probe_id),
                        params=self._query_params(),
                    )
                    elapsed = (time.perf_counter() - t0) * 1000
                    if resp.status_code == 429 and attempt < max_retries:
                        ra = float(resp.headers.get("retry-after", 2 * (attempt + 1)))
                        logger.warning(f"429, retry {attempt+1} after {ra}s")
                        await asyncio.sleep(ra)
                        continue
                    body = None
                    try: body = resp.json()
                    except (json.JSONDecodeError, ValueError): pass
                    return ProbeResponse(
                        status_code=resp.status_code, body=body,
                        headers=dict(resp.headers), raw_text=resp.text,
                        latency_ms=elapsed)
                except httpx.TimeoutException:
                    if attempt < max_retries:
                        logger.warning(f"Timeout, retry {attempt+1}")
                        await asyncio.sleep(1)
                        continue
                    return ProbeResponse(status_code=0, error="TIMEOUT",
                        latency_ms=(time.perf_counter()-t0)*1000)
                except httpx.ConnectError as e:
                    return ProbeResponse(status_code=0, error=f"CONNECT: {e}",
                        latency_ms=(time.perf_counter()-t0)*1000)
                except httpx.HTTPError as e:
                    return ProbeResponse(status_code=0, error=f"HTTP: {e}",
                        latency_ms=(time.perf_counter()-t0)*1000)
        return ProbeResponse(status_code=0, error="MAX_RETRIES")

    async def get(self, path: str, params: dict[str, str] | None = None) -> ProbeResponse:
        probe_id = str(uuid.uuid4())[:8]
        async with self._semaphore:
            await self._throttle()
            t0 = time.perf_counter()
            try:
                all_params = {**(self._query_params() or {}), **(params or {})}
                resp = await self._client.get(
                    self._url(path),
                    headers=self._headers(probe_id),
                    params=all_params if all_params else None,
                )
                elapsed = (time.perf_counter() - t0) * 1000
                body = None
                try: body = resp.json()
                except (json.JSONDecodeError, ValueError): pass
                return ProbeResponse(
                    status_code=resp.status_code, body=body,
                    headers=dict(resp.headers), raw_text=resp.text,
                    latency_ms=elapsed)
            except httpx.TimeoutException:
                return ProbeResponse(status_code=0, error="GET_TIMEOUT",
                    latency_ms=(time.perf_counter()-t0)*1000)
            except httpx.HTTPError as e:
                return ProbeResponse(status_code=0, error=f"GET: {e}",
                    latency_ms=(time.perf_counter()-t0)*1000)

    async def send_stream(self, probe: ProbeRequest) -> ProbeResponse:
        probe_id = str(uuid.uuid4())[:8]
        async with self._semaphore:
            await self._throttle()
            t0 = time.perf_counter()
            chunks, timestamps, content = [], [], ""
            usage_block, finish_reason = None, None
            status_code, headers = 0, {}
            try:
                payload = {**probe.payload, "stream": True}
                async with aconnect_sse(
                    self._client, "POST",
                    self._url(probe.endpoint_path),
                    json=payload,
                    headers=self._headers(probe_id),
                    params=self._query_params(),
                ) as es:
                    status_code = es.response.status_code
                    headers = dict(es.response.headers)
                    async for event in es.aiter_sse():
                        if event.data == "[DONE]": break
                        timestamps.append(time.perf_counter() - t0)
                        try:
                            chunk = json.loads(event.data)
                            chunks.append(chunk)
                            choices = chunk.get("choices", [])
                            if choices:
                                delta = choices[0].get("delta", {})
                                c = delta.get("content", "")
                                if c: content += c
                                fr = choices[0].get("finish_reason")
                                if fr: finish_reason = fr
                            if "usage" in chunk:
                                usage_block = chunk["usage"]
                        except (json.JSONDecodeError, ValueError):
                            chunks.append({"_raw": event.data})
            except (httpx.TimeoutException, httpx.HTTPError) as e:
                return ProbeResponse(status_code=0, error=f"STREAM: {e}",
                    latency_ms=(time.perf_counter()-t0)*1000)
            return ProbeResponse(
                status_code=status_code,
                body={"full_content": content, "chunk_count": len(chunks),
                      "finish_reason": finish_reason, "usage": usage_block},
                headers=headers, raw_text=content,
                latency_ms=(time.perf_counter()-t0)*1000,
                chunks=chunks, chunk_timestamps=timestamps)

    async def send_concurrent(self, probes: list[ProbeRequest]) -> list[ProbeResponse]:
        return list(await asyncio.gather(*[self.send(p) for p in probes]))
```

---

## 六、detectors/__init__.py

```python
import importlib, pkgutil, pathlib
_pkg = pathlib.Path(__file__).parent
for m in pkgutil.iter_modules([str(_pkg)]):
    if m.name.startswith("d"):
        importlib.import_module(f".{m.name}", __package__)
```

---

## 七、events.py

```python
from __future__ import annotations
import logging
from typing import Any, Callable
from enum import Enum

logger = logging.getLogger("router-auditor.events")


class EventType(str, Enum):
    TEST_START = "test_start"
    TEST_END = "test_end"
    STAGE_START = "stage_start"
    STAGE_END = "stage_end"
    DETECTOR_START = "detector_start"
    DETECTOR_END = "detector_end"
    PROBE_SENT = "probe_sent"
    PROBE_RECEIVED = "probe_received"
    ABORT = "abort"
    CONTRADICTION = "contradiction"


class Event:
    def __init__(self, type: EventType, data: dict[str, Any] | None = None):
        self.type = type
        self.data = data or {}


class EventBus:
    def __init__(self):
        self._handlers: dict[EventType, list[Callable]] = {}

    def on(self, event_type: EventType, handler: Callable):
        self._handlers.setdefault(event_type, []).append(handler)
        return self

    def emit(self, event: Event):
        for handler in self._handlers.get(event.type, []):
            try:
                handler(event)
            except Exception as e:
                logger.error(f"Event handler error: {e}")

    def off(self, event_type: EventType, handler: Callable):
        handlers = self._handlers.get(event_type, [])
        if handler in handlers:
            handlers.remove(handler)
```

---

## 八、registry.py

```python
from __future__ import annotations
import time
import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Any, ClassVar
from .models import (
    Priority, JudgeMode, ProviderType, Capability, AuthMethod,
    DetectorResult, Verdict, ProbeResponse, TestConfig,
)
from .client import RouterClient
from .events import EventBus, EventType, Event

logger = logging.getLogger("router-auditor.detector")
_REGISTRY: dict[str, type[BaseDetector]] = {}


def detector(cls: type[BaseDetector]) -> type[BaseDetector]:
    _REGISTRY[cls.detector_id] = cls
    return cls

def get_all_detectors() -> dict[str, type[BaseDetector]]:
    return dict(_REGISTRY)


class BaseDetector(ABC):
    detector_id: ClassVar[str]
    detector_name: ClassVar[str]
    priority: ClassVar[Priority]
    judge_mode: ClassVar[JudgeMode]
    request_count: ClassVar[int] = 1
    detector_timeout: ClassVar[float] = 30.0
    required_capabilities: ClassVar[list[Capability]] = [Capability.TEXT]
    required_provider: ClassVar[ProviderType] = ProviderType.ANY
    requires_direct: ClassVar[bool] = False
    requires_single_route_claim: ClassVar[bool] = False
    depends_on: ClassVar[list[str]] = []
    description: ClassVar[str] = ""

    def __init__(self, config: TestConfig, client: RouterClient,
                 shared_context: dict[str, Any] | None = None,
                 event_bus: EventBus | None = None):
        self.config = config
        self.client = client
        self.shared = shared_context or {}
        self.events = event_bus or EventBus()

    @property
    def has_direct(self) -> bool:
        return bool(self.config.direct_endpoint and self.config.direct_api_key)

    def make_direct_client(self) -> RouterClient:
        return RouterClient(
            endpoint=self.config.direct_endpoint,
            api_key=self.config.direct_api_key,
            auth_method=self.config.direct_auth_method or self.config.auth_method,
            timeout=self.config.timeout,
            max_concurrent=self.config.max_concurrent,
            min_interval=self.config.min_request_interval,
        )

    def should_skip(self) -> str | None:
        for cap in self.required_capabilities:
            if cap not in self.config.capabilities:
                return f"requires {cap.value}"
        if (self.required_provider != ProviderType.ANY
                and self.config.claimed_provider != self.required_provider):
            return f"requires {self.required_provider.value}"
        if self.requires_single_route_claim and not self.config.claimed_single_route:
            return "requires single provider claim"
        return None

    @abstractmethod
    async def send_probes(self) -> list[ProbeResponse]: ...

    @abstractmethod
    def judge(self, responses: list[ProbeResponse]) -> DetectorResult: ...

    async def run(self) -> DetectorResult:
        skip = self.should_skip()
        if skip:
            logger.info(f"[{self.detector_id}] SKIP: {skip}")
            return self._skip(skip)

        self.events.emit(Event(EventType.DETECTOR_START, {
            "id": self.detector_id, "name": self.detector_name}))
        logger.info(f"[{self.detector_id}] starting {self.detector_name}...")
        t0 = time.perf_counter()

        try:
            result = await asyncio.wait_for(
                self._execute(), timeout=self.detector_timeout)
        except asyncio.TimeoutError:
            logger.error(f"[{self.detector_id}] timed out ({self.detector_timeout}s)")
            result = self._inconclusive(f"timed out after {self.detector_timeout}s")
        except Exception as e:
            logger.error(f"[{self.detector_id}] error: {e}", exc_info=True)
            result = self._inconclusive(f"error: {e}")

        result.latency_ms = (time.perf_counter() - t0) * 1000
        result.request_count = self.request_count
        logger.info(f"[{self.detector_id}] {result.verdict.value} ({result.latency_ms:.0f}ms)")

        self.events.emit(Event(EventType.DETECTOR_END, {
            "id": self.detector_id, "verdict": result.verdict.value,
            "latency_ms": result.latency_ms}))
        return result

    async def _execute(self) -> DetectorResult:
        if self.judge_mode == JudgeMode.MAJORITY_2_OF_2:
            return await self._run_majority()
        responses = await self.send_probes()
        net_errors = [r for r in responses if r.is_network_error]
        if net_errors and len(net_errors) == len(responses):
            return self._inconclusive(f"all probes failed: {net_errors[0].error}")
        return self.judge(responses)

    async def _run_majority(self) -> DetectorResult:
        results = []
        for i in range(2):
            responses = await self.send_probes()
            net_errors = [r for r in responses if r.is_network_error]
            if net_errors and len(net_errors) == len(responses):
                return self._inconclusive(f"all probes failed: {net_errors[0].error}")
            results.append(self.judge(responses))
        fails = sum(1 for r in results if r.verdict == Verdict.FAIL)
        if fails == 2:
            f = results[0]
            f.confidence = 0.95
            f.evidence["majority"] = "2/2 FAIL"
            return f
        elif fails == 1:
            return DetectorResult(
                detector_id=self.detector_id, detector_name=self.detector_name,
                priority=self.priority, verdict=Verdict.SUSPICIOUS, confidence=0.5,
                evidence={"majority": "1/2 FAIL",
                          "run_1": results[0].evidence, "run_2": results[1].evidence})
        return results[0]

    def _pass(self, evidence=None):
        return DetectorResult(detector_id=self.detector_id, detector_name=self.detector_name,
            priority=self.priority, verdict=Verdict.PASS, confidence=1.0,
            evidence=evidence or {})

    def _fail(self, reason, evidence=None, confidence=1.0):
        return DetectorResult(detector_id=self.detector_id, detector_name=self.detector_name,
            priority=self.priority, verdict=Verdict.FAIL, confidence=confidence,
            evidence={"reason": reason, **(evidence or {})})

    def _fail_degraded(self, reason, evidence=None):
        return self._fail(reason, evidence, confidence=0.70)

    def _inconclusive(self, reason):
        return DetectorResult(detector_id=self.detector_id, detector_name=self.detector_name,
            priority=self.priority, verdict=Verdict.INCONCLUSIVE, confidence=0.0,
            evidence={"reason": reason})

    def _skip(self, reason):
        return DetectorResult(detector_id=self.detector_id, detector_name=self.detector_name,
            priority=self.priority, verdict=Verdict.SKIP, confidence=0.0,
            skipped_reason=reason)

    @classmethod
    def self_test(cls):
        cases = cls._test_cases()
        if not cases:
            print(f"⚠️  {cls.detector_id}: no test cases"); return
        passed = 0
        for name, mock_resps, expected in cases:
            from unittest.mock import MagicMock
            inst = cls.__new__(cls)
            inst.config = MagicMock()
            inst.client = MagicMock()
            inst.shared = {}
            inst.events = MagicMock()
            inst.config.claimed_model = "gpt-4o"
            inst.config.claimed_provider = ProviderType.ANY
            r = inst.judge(mock_resps)
            if r.verdict.value == expected:
                passed += 1; print(f"  ✅ {name}")
            else:
                print(f"  ❌ {name}: expected {expected}, got {r.verdict.value}")
        print(f"{'✅' if passed == len(cases) else '❌'} {cls.detector_id}: {passed}/{len(cases)}")

    @classmethod
    def _test_cases(cls):
        return []
```

---

## 九、runner.py

```python
from __future__ import annotations
import asyncio
import logging
import signal
from datetime import datetime, timezone
from typing import Any

from .models import TestConfig, TestReport, DetectorResult, Priority, Verdict
from .registry import get_all_detectors, BaseDetector
from .client import RouterClient
from .events import EventBus, EventType, Event

logger = logging.getLogger("router-auditor.runner")

STAGES = [
    {"name": "pre_screen", "priorities": [Priority.PRE_SCREEN],
     "abort_on_fail": False, "parallel": False},
    {"name": "s0", "priorities": [Priority.S0],
     "abort_on_fail": True, "parallel": True},
    {"name": "p0", "priorities": [Priority.P0],
     "abort_on_fail": True, "parallel": False},
    {"name": "p1", "priorities": [Priority.P1],
     "abort_on_fail": False, "parallel": False},
    {"name": "p2", "priorities": [Priority.P2],
     "abort_on_fail": False, "parallel": True},
]


class TestRunner:
    def __init__(self, config: TestConfig, only: list[str] | None = None,
                 event_bus: EventBus | None = None):
        self.config = config
        self.only = only
        self.events = event_bus or EventBus()
        self.results: list[DetectorResult] = []
        self.shared_context: dict[str, Any] = {}
        self.on_progress: Any = None
        self._interrupted = False

    def _get_applicable_detectors(self) -> dict[str, type[BaseDetector]]:
        all_cls = get_all_detectors()
        if self.only:
            all_cls = {k: v for k, v in all_cls.items() if k in self.only}
        return all_cls

    async def run_all(self) -> TestReport:
        loop = asyncio.get_running_loop()
        try:
            loop.add_signal_handler(signal.SIGINT, self._handle_interrupt)
        except NotImplementedError:
            pass

        all_cls = self._get_applicable_detectors()
        total = len(all_cls)
        completed = 0
        aborted, abort_reason = False, ""

        self.events.emit(Event(EventType.TEST_START, {
            "endpoint": self.config.router_endpoint, "detectors": total}))

        async with RouterClient(
            endpoint=self.config.router_endpoint,
            api_key=self.config.api_key,
            auth_method=self.config.auth_method,
            extra_headers=self.config.extra_headers,
            timeout=self.config.timeout,
            max_concurrent=self.config.max_concurrent,
            min_interval=self.config.min_request_interval,
        ) as client:
            for stage in STAGES:
                stage_cls = {k: v for k, v in all_cls.items()
                             if v.priority in stage["priorities"]}
                if not stage_cls:
                    continue

                if self._interrupted or aborted:
                    reason = "user interrupted" if self._interrupted else abort_reason
                    for c in stage_cls.values():
                        self.results.append(self._make_skip(c, reason))
                    completed += len(stage_cls)
                    self._report_progress(completed, total)
                    continue

                self.events.emit(Event(EventType.STAGE_START, {
                    "name": stage["name"], "count": len(stage_cls)}))

                dets = sorted(
                    [c(self.config, client, self.shared_context, self.events)
                     for c in stage_cls.values()],
                    key=lambda d: d.detector_id)

                logger.info(f"=== {stage['name'].upper()} ({len(dets)}) ===")

                if stage["parallel"] and len(dets) > 1:
                    results = await self._parallel(dets)
                else:
                    results = await self._sequential(dets)

                self.results.extend(results)
                completed += len(results)
                self._report_progress(completed, total)

                self.events.emit(Event(EventType.STAGE_END, {
                    "name": stage["name"],
                    "results": [{"id": r.detector_id, "verdict": r.verdict.value}
                                for r in results]}))

                if stage["abort_on_fail"]:
                    fails = [r for r in results if r.verdict == Verdict.FAIL]
                    if fails:
                        aborted = True
                        abort_reason = f"{stage['name'].upper()}: {fails[0].detector_id}"
                        logger.warning(f"ABORT: {abort_reason}")
                        self.events.emit(Event(EventType.ABORT, {"reason": abort_reason}))

        report = self._build_report()
        if self._interrupted:
            report.tier_assignment = f"PARTIAL ({report.tier_assignment})"
        self.events.emit(Event(EventType.TEST_END, {
            "verdict": report.overall_verdict.value, "tier": report.tier_assignment}))
        return report

    async def _sequential(self, dets):
        results = []
        for d in dets:
            if self._interrupted:
                results.append(self._make_skip(type(d), "user interrupted"))
                continue
            r = await d.run()
            results.append(r)
            self.shared_context[d.detector_id] = {"result": r, "evidence": r.evidence}
        return results

    async def _parallel(self, dets):
        indep = [d for d in dets if not d.depends_on]
        dep = [d for d in dets if d.depends_on]
        results = []
        if indep:
            par = list(await asyncio.gather(*[d.run() for d in indep]))
            results.extend(par)
            for d, r in zip(indep, par):
                self.shared_context[d.detector_id] = {"result": r, "evidence": r.evidence}
        for d in dep:
            r = await d.run()
            results.append(r)
            self.shared_context[d.detector_id] = {"result": r, "evidence": r.evidence}
        return results

    def _handle_interrupt(self):
        logger.warning("Interrupted!")
        self._interrupted = True

    def _report_progress(self, completed, total):
        if self.on_progress:
            self.on_progress(completed, total)

    def _build_report(self):
        p = sum(1 for r in self.results if r.verdict == Verdict.PASS)
        f = sum(1 for r in self.results if r.verdict == Verdict.FAIL)
        s = sum(1 for r in self.results if r.verdict == Verdict.SUSPICIOUS)
        k = sum(1 for r in self.results if r.verdict == Verdict.SKIP)

        s0f = any(r.verdict == Verdict.FAIL and r.priority == Priority.S0 for r in self.results)
        p0f = any(r.verdict == Verdict.FAIL and r.priority == Priority.P0 for r in self.results)
        p1f = any(r.verdict == Verdict.FAIL and r.priority == Priority.P1 for r in self.results)

        if s0f or p0f: ov, tier = Verdict.FAIL, "BLACKLIST"
        elif p1f: ov, tier = Verdict.PASS, "TIER_2"
        elif s > 0: ov, tier = Verdict.PASS, "TIER_1_WATCH"
        else: ov, tier = Verdict.PASS, "TIER_1"

        return TestReport(
            router_endpoint=self.config.router_endpoint,
            test_timestamp=datetime.now(timezone.utc).isoformat(),
            overall_verdict=ov, tier_assignment=tier,
            total_detectors=len(self.results),
            passed=p, failed=f, suspicious=s, skipped=k,
            total_requests=sum(r.request_count for r in self.results if r.verdict != Verdict.SKIP),
            total_latency_ms=sum(r.latency_ms for r in self.results),
            estimated_cost_usd=0.68, results=self.results,
            evidence_notes=self._detect_contradictions())

    def _detect_contradictions(self):
        notes = []
        rm = {r.detector_id: r for r in self.results}
        d31 = rm.get("D31")
        if d31 and d31.verdict == Verdict.PASS:
            for did in ["D21", "D22", "D23"]:
                d = rm.get(did)
                if d and d.verdict == Verdict.FAIL:
                    notes.append(f"D31 PASS but {did} FAIL")
        d24a, d29 = rm.get("D24a"), rm.get("D29")
        if d24a and d29 and d24a.verdict == Verdict.PASS and d29.verdict == Verdict.FAIL:
            notes.append("D24a PASS but D29 FAIL: billing inflated")
        d25, d54 = rm.get("D25"), rm.get("D54")
        if d25 and d54 and d25.verdict == Verdict.PASS and d54.verdict == Verdict.FAIL:
            notes.append("D25 PASS but D54 FAIL: semantic truncation")
        return notes

    @staticmethod
    def _make_skip(cls, reason):
        return DetectorResult(
            detector_id=cls.detector_id, detector_name=cls.detector_name,
            priority=cls.priority, verdict=Verdict.SKIP, confidence=0.0,
            skipped_reason=reason)
```

---

## 十、tokenizer.py

```python
from __future__ import annotations
import logging

logger = logging.getLogger("router-auditor.tokenizer")


class TokenCounter:
    def __init__(self):
        self._enc: dict = {}

    def count(self, text: str, model: str = "gpt-4o") -> int:
        enc = self._get(model)
        return len(enc.encode(text)) if enc else len(text) // 4

    def get_token_id(self, text: str, model: str = "gpt-4o") -> int | None:
        enc = self._get(model)
        if enc:
            ids = enc.encode(text)
            return ids[0] if len(ids) == 1 else None
        return None

    def find_single_token(self, candidates: list[str], model: str = "gpt-4o"):
        enc = self._get(model)
        if not enc:
            return None
        for w in candidates:
            ids = enc.encode(w)
            if len(ids) == 1:
                return w, ids[0]
        return None

    def tokenize(self, text: str, model: str = "gpt-4o") -> list[str]:
        enc = self._get(model)
        if not enc:
            return list(text)
        return [enc.decode([t]) for t in enc.encode(text)]

    def _get(self, model):
        if model in self._enc:
            return self._enc[model]
        try:
            import tiktoken
            e = tiktoken.encoding_for_model(model)
        except Exception:
            try:
                import tiktoken
                e = tiktoken.get_encoding("cl100k_base")
            except Exception:
                e = None
        self._enc[model] = e
        return e


token_counter = TokenCounter()
```

---

## 十一、config.py

```python
# logit_bias 候选词（D21b）
LOGIT_BIAS_CANDIDATES = [" the", " a", " is", " to", " of", " and"]

# 分词器指纹（D4a）
# 预计算的已知分词结果。D4a 实现时应在 __init__ 中用 tiktoken 动态生成
# 本模型族的标准指纹，这里只是 fallback 参考。
TOKENIZER_FINGERPRINTS = {
    "SolidGoldMagikarp": {
        "openai_cl100k": ["Solid", "Gold", "Mag", "ik", "arp"],
        "openai_o200k": ["Solid", "Gold", "Mag", "ikarp"],
    },
    "sjkldfjsldkfj": {
        "openai_cl100k": ["sj", "kl", "df", "js", "ld", "kf", "j"],
        "openai_o200k": ["sjk", "ldf", "jsld", "kfj"],
    },
    " petertodd": {
        "openai_cl100k": [" peter", "todd"],
        "openai_o200k": [" peter", "todd"],
    },
}

# D4a 应在运行时动态生成当前模型的标准指纹：
# from src.tokenizer import token_counter
# actual = token_counter.tokenize("SolidGoldMagikarp", model=claimed_model)
# 然后与模型返回的分词结果比对。不要只依赖上面的硬编码表。

# D4a 测试字符串（不要修改，这些字符串经过精心选择）
TOKENIZER_PROBE_STRINGS = [
    "SolidGoldMagikarp",   # GPT 系列 glitch token
    "sjkldfjsldkfj",       # 无意义字符串，各模型分词差异大
    " petertodd",          # 前导空格 + 人名，分词敏感
]

# 参数边界（D22d/D30a）
PROVIDER_PARAM_LIMITS = {
    "openai": {"temperature_max": 2.0},
    "anthropic": {"temperature_max": 1.0},
    "gemini": {"temperature_max": 2.0},
}

# 伪造错误特征（D30）
KNOWN_FAKE_PATTERNS = [
    "new_api_error", "one_api_error", "<html", "<!doctype",
    "cloudflare", "ray id", "captcha_required", "poe daily limit",
    "usage quota exceeded", "nginx", "502 bad gateway",
]

# 劫持号关键词（D23）
HIJACKED_KEYWORDS = [
    "cursor", "monica", "translate", "翻译", "translation",
    "作业", "homework", "code assistant", "copilot",
]

# Provider 标准 headers（D30）
KNOWN_PROVIDER_HEADERS = {
    "x-request-id", "x-ratelimit-limit-requests", "cf-ray",
}
```

---

## 十二、utils/

### utils/__init__.py
```python
```

### utils/nonce.py
```python
import random
import string
import time


def generate_nonce(prefix: str = "NONCE", length: int = 8) -> str:
    chars = string.ascii_uppercase + string.digits
    return f"{prefix}-{''.join(random.choices(chars, k=length))}"


def generate_timestamp_nonce() -> str:
    return f"TS-{int(time.time())}-{random.randint(1000, 9999)}"


def generate_canary(prefix: str = "CANARY") -> str:
    return generate_nonce(prefix, 12)
```

### utils/eth.py
```python
import secrets


def _keccak256(data: bytes) -> bytes:
    try:
        from Crypto.Hash import keccak
        return keccak.new(digest_bits=256, data=data).digest()
    except ImportError:
        pass
    try:
        import sha3
        return sha3.keccak_256(data).digest()
    except ImportError:
        pass
    import hashlib
    return hashlib.sha3_256(data).digest()


def generate_test_eth_address() -> str:
    raw = secrets.token_bytes(20)
    addr_lower = raw.hex()
    addr_hash = _keccak256(addr_lower.encode("ascii")).hex()
    checksummed = []
    for i, c in enumerate(addr_lower):
        if c in "0123456789":
            checksummed.append(c)
        elif int(addr_hash[i], 16) >= 8:
            checksummed.append(c.upper())
        else:
            checksummed.append(c)
    return "0x" + "".join(checksummed)


def is_valid_eth_address(addr: str) -> bool:
    if not addr.startswith("0x") or len(addr) != 42:
        return False
    try:
        int(addr[2:], 16)
        return True
    except ValueError:
        return False


if __name__ == "__main__":
    for _ in range(10):
        addr = generate_test_eth_address()
        assert is_valid_eth_address(addr)
        print(f"  ✅ {addr}")
    print("✅ ETH: 10/10 passed")
```

### utils/text_analysis.py
```python
import re

_COMMON = {
    "the", "a", "an", "is", "are", "was", "were", "be", "have", "has", "had",
    "do", "does", "did", "will", "would", "could", "should", "can", "i", "you",
    "he", "she", "it", "we", "they", "and", "or", "but", "not", "no", "so",
    "if", "of", "in", "on", "at", "to", "for", "with", "from", "by", "as",
    "this", "that", "my", "your", "his", "her", "its", "our", "their",
}


def readable_bigram_ratio(text: str) -> float:
    words = re.findall(r"[a-zA-Z]+", text.lower())
    if len(words) < 3:
        return 1.0
    pairs = sum(1 for i in range(len(words) - 1)
                if words[i] in _COMMON and words[i + 1] in _COMMON)
    return pairs / (len(words) - 1)


def count_negations(text: str) -> int:
    negs = {
        "not", "no", "never", "don't", "doesn't", "didn't", "isn't", "aren't",
        "won't", "wouldn't", "couldn't", "shouldn't", "cannot", "can't",
        "不", "没有", "无法", "切勿", "禁止", "不要", "不会", "未",
    }
    return sum(1 for w in re.findall(r"[\w']+", text.lower()) if w in negs)
```

### utils/timing.py
```python
import statistics


def analyze_chunks(timestamps: list[float]) -> dict:
    if len(timestamps) < 3:
        return {"analyzable": False, "count": len(timestamps)}
    itv = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
    m = statistics.mean(itv)
    return {
        "analyzable": True,
        "count": len(timestamps),
        "ttfb_s": timestamps[0],
        "mean_ms": m * 1000,
        "stdev_ms": statistics.stdev(itv) * 1000 if len(itv) > 1 else 0,
        "cv": statistics.stdev(itv) / m if m > 0 else 0,
    }
```

---

## 十三、assets.py

```python
from __future__ import annotations
import base64
import io
import math
import random
import string
import struct
from typing import Any

_asset_cache: dict[str, Any] = {}


def generate_probe_image(
    code: str | None = None,
    size: tuple[int, int] = (4000, 4000),
    font_size: int = 16,
    fill: tuple[int, int, int] = (120, 120, 120),
    position: tuple[int, int] = (3800, 3800),
) -> tuple[bytes, str]:
    from PIL import Image, ImageDraw
    if code is None:
        code = _random_code(6)
    img = Image.new("RGB", size, "white")
    draw = ImageDraw.Draw(img)
    font = _get_font(font_size)
    draw.text(position, code, fill=fill, font=font)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue(), code


def generate_nonce_image(text: str, size: tuple[int, int] = (800, 200)) -> bytes:
    from PIL import Image, ImageDraw
    img = Image.new("RGB", size, "white")
    draw = ImageDraw.Draw(img)
    font = _get_font(48)
    draw.text((50, 70), text, fill=(0, 0, 0), font=font)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def generate_probe_pdf(nonce: str = "PDF-NONCE-MID-55K") -> tuple[bytes, str]:
    import pymupdf
    doc = pymupdf.open()
    for page_num in range(3):
        page = doc.new_page(width=612, height=792)
        y = 72
        if page_num == 1:
            page.insert_text((72, y), nonce,
                             fontsize=16, fontname="helv", color=(0, 0, 0))
            y += 30
        for i in range(20):
            page.insert_text((72, y + i * 18),
                             f"Filler content line {i+1} on page {page_num+1}.",
                             fontsize=11, fontname="helv", color=(0.3, 0.3, 0.3))
    pdf_bytes = doc.tobytes()
    verify = pymupdf.open(stream=pdf_bytes, filetype="pdf")
    assert nonce in verify[1].get_text(), "Self-check failed"
    verify.close()
    doc.close()
    return pdf_bytes, nonce


def generate_probe_pdf_with_image(nonce: str = "PDF-IMG-X9K2") -> tuple[bytes, str]:
    import pymupdf
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((72, 72), nonce, fontsize=14, fontname="helv")
    img_bytes = generate_nonce_image(f"IMG-IN-PDF-{_random_code(4)}")
    page.insert_image(pymupdf.Rect(72, 120, 400, 280), stream=img_bytes)
    pdf_bytes = doc.tobytes()
    doc.close()
    return pdf_bytes, nonce


def render_pdf_page_to_image(pdf_bytes: bytes, page_num: int = 0, dpi: int = 150) -> bytes:
    import pymupdf
    doc = pymupdf.open(stream=pdf_bytes, filetype="pdf")
    pix = doc[page_num].get_pixmap(dpi=dpi)
    img = pix.tobytes("png")
    doc.close()
    return img


def extract_pdf_text(pdf_bytes: bytes, page_num: int | None = None) -> str:
    import pymupdf
    doc = pymupdf.open(stream=pdf_bytes, filetype="pdf")
    if page_num is not None:
        text = doc[page_num].get_text()
    else:
        text = "\n\n".join(p.get_text() for p in doc)
    doc.close()
    return text


def generate_probe_audio(text: str = "CRIMSON FORTY TWO") -> tuple[bytes, str] | tuple[None, str]:
    """
    生成包含指定文本的真人语音 WAV。
    三级 fallback：espeak (Linux) → say (macOS) → None (SKIP)。
    不使用合成音调——多模态模型无法从频率序列中提取文字。
    """
    import subprocess
    import tempfile
    from pathlib import Path

    # 1. Linux: espeak
    try:
        with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
            subprocess.run(
                ["espeak", "-w", f.name, "-s", "130", text],
                check=True, capture_output=True, timeout=10,
            )
            return Path(f.name).read_bytes(), text
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        pass

    # 2. macOS: say + afconvert
    try:
        with tempfile.NamedTemporaryFile(suffix=".aiff", delete=False) as f:
            subprocess.run(
                ["say", "-o", f.name, text],
                check=True, capture_output=True, timeout=10,
            )
            wav_path = f.name.replace(".aiff", ".wav")
            subprocess.run(
                ["afconvert", "-f", "WAVE", "-d", "LEI16", f.name, wav_path],
                check=True, capture_output=True,
            )
            return Path(wav_path).read_bytes(), text
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        pass

    # 3. 都不可用 → 返回 None，Detector 自动 SKIP
    return None, text


def _random_code(n=6):
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=n))

def _get_font(size):
    from PIL import ImageFont
    for p in ["/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
              "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
              "/System/Library/Fonts/Helvetica.ttc",
              "C:\\Windows\\Fonts\\arial.ttf"]:
        try: return ImageFont.truetype(p, size)
        except OSError: continue
    return ImageFont.load_default()

def _tone(sr, f, d, a=0.8):
    return b"".join(
        struct.pack("<h", max(-32768, min(32767,
            int(a * 32767 * math.sin(2 * math.pi * f * i / sr)))))
        for i in range(int(sr * d)))

def _silence(sr, d):
    return b"\x00\x00" * int(sr * d)

def _noise(sr, d, a=0.05):
    return b"".join(
        struct.pack("<h", int(a * 32767 * (random.random() * 2 - 1)))
        for _ in range(int(sr * d)))

def _mix(a, b):
    n = min(len(a), len(b)) // 2
    r = b"".join(
        struct.pack("<h", max(-32768, min(32767,
            struct.unpack_from("<h", a, i * 2)[0] + struct.unpack_from("<h", b, i * 2)[0])))
        for i in range(n))
    return r + a[n * 2:] if len(a) > len(b) else r

def _wav(raw, sr):
    buf = io.BytesIO()
    buf.write(b"RIFF")
    buf.write(struct.pack("<I", 36 + len(raw)))
    buf.write(b"WAVEfmt ")
    buf.write(struct.pack("<IHHIIHH", 16, 1, 1, sr, sr * 2, 2, 16))
    buf.write(b"data")
    buf.write(struct.pack("<I", len(raw)))
    buf.write(raw)
    return buf.getvalue()

def to_base64(data: bytes) -> str:
    return base64.b64encode(data).decode()

def to_data_url(data: bytes, media_type: str) -> str:
    return f"data:{media_type};base64,{to_base64(data)}"


def _cache_key(prefix: str, **kw) -> str:
    return f"{prefix}_{repr(sorted(kw.items()))}"

def get_probe_image(**kw):
    k = _cache_key("img", **kw)
    return _asset_cache.setdefault(k, generate_probe_image(**kw))

def get_nonce_image(text: str):
    return _asset_cache.setdefault(f"ni_{text}", generate_nonce_image(text))

def get_probe_pdf(**kw):
    k = _cache_key("pdf", **kw)
    return _asset_cache.setdefault(k, generate_probe_pdf(**kw))

def get_probe_audio(**kw):
    k = _cache_key("aud", **kw)
    return _asset_cache.setdefault(k, generate_probe_audio(**kw))
```

---

## 十四、reporter.py

```python
from __future__ import annotations
import json
from .models import TestReport, Verdict


def print_cli_report(report: TestReport):
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        _print_rich(report)
    except ImportError:
        _print_plain(report)


def _print_rich(report: TestReport):
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel

    c = Console()
    vc = "green" if report.overall_verdict == Verdict.PASS else "red"
    c.print(Panel(
        f"[bold {vc}]{report.overall_verdict.value.upper()}[/] → {report.tier_assignment}\n"
        f"{report.passed}P {report.failed}F {report.suspicious}S {report.skipped}K | "
        f"{report.total_latency_ms / 1000:.1f}s | ${report.estimated_cost_usd:.2f}",
        title=report.router_endpoint))

    t = Table(show_header=True)
    for col in ["ID", "Name", "Pri", "Verdict", "Time", "Detail"]:
        t.add_column(col)

    styles = {
        Verdict.PASS: "green", Verdict.FAIL: "bold red",
        Verdict.SUSPICIOUS: "yellow", Verdict.SKIP: "dim",
        Verdict.INCONCLUSIVE: "dim yellow",
    }
    for r in report.results:
        s = styles.get(r.verdict, "")
        detail = r.skipped_reason or r.evidence.get("reason", "")
        t.add_row(
            r.detector_id, r.detector_name, r.priority.value,
            f"[{s}]{r.verdict.value.upper()}[/{s}]",
            f"{r.latency_ms:.0f}ms", str(detail)[:40])
    c.print(t)

    if report.evidence_notes:
        c.print("\n[yellow]⚠️  Contradictions:[/]")
        for note in report.evidence_notes:
            c.print(f"  • {note}")


def _print_plain(report: TestReport):
    print(f"\n{'=' * 60}")
    print(f"Router: {report.router_endpoint}")
    print(f"Verdict: {report.overall_verdict.value.upper()} → {report.tier_assignment}")
    print(f"Results: {report.passed}P {report.failed}F {report.suspicious}S {report.skipped}K")
    print(f"{'=' * 60}")

    flags = {"pass": "✅", "fail": "❌", "suspicious": "⚠️",
             "skip": "⏭️", "inconclusive": "❓"}
    for r in report.results:
        print(f"  {flags.get(r.verdict.value, '?')} [{r.priority.value}] "
              f"{r.detector_id} {r.detector_name} ({r.latency_ms:.0f}ms)")
        if r.verdict == Verdict.FAIL:
            print(f"     → {r.evidence.get('reason', '')}")

    if report.evidence_notes:
        print("\n⚠️  Contradictions:")
        for note in report.evidence_notes:
            print(f"  • {note}")

    print(f"\nTotal: {report.total_latency_ms / 1000:.1f}s | "
          f"~${report.estimated_cost_usd:.2f}")


def write_junit_xml(report: TestReport, path: str):
    import xml.etree.ElementTree as ET

    suite = ET.Element("testsuite", {
        "name": "router-auditor",
        "tests": str(report.total_detectors),
        "failures": str(report.failed),
        "skipped": str(report.skipped),
        "time": f"{report.total_latency_ms / 1000:.2f}",
    })

    for r in report.results:
        tc = ET.SubElement(suite, "testcase", {
            "classname": f"router_auditor.{r.priority.value}",
            "name": f"{r.detector_id}_{r.detector_name}",
            "time": f"{r.latency_ms / 1000:.2f}",
        })
        if r.verdict == Verdict.FAIL:
            fail = ET.SubElement(tc, "failure", {
                "message": r.evidence.get("reason", "unknown"),
                "type": r.priority.value,
            })
            fail.text = json.dumps(r.evidence, indent=2)
        elif r.verdict == Verdict.SKIP:
            ET.SubElement(tc, "skipped", {"message": r.skipped_reason or ""})
        elif r.verdict == Verdict.SUSPICIOUS:
            fail = ET.SubElement(tc, "failure", {
                "message": f"SUSPICIOUS: {r.evidence.get('majority', '')}",
                "type": "suspicious",
            })

    tree = ET.ElementTree(suite)
    ET.indent(tree, space="  ")
    tree.write(path, encoding="unicode", xml_declaration=True)
```

---

## 十五、api/app.py

```python
from __future__ import annotations
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .routes import router, set_task_manager
from .task_manager import TaskManager

logger = logging.getLogger("router-auditor.api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    tm = TaskManager(max_concurrent=3)
    set_task_manager(tm)
    logger.info("Router Auditor API started")
    yield
    logger.info("Router Auditor API shutting down")


def create_app() -> FastAPI:
    app = FastAPI(
        title="Router Auditor API",
        description="LLM Router 准入检测 API",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(router)
    return app


app = create_app()
```

---

## 十六、api/auth.py

```python
from __future__ import annotations
import os
from fastapi import HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security = HTTPBearer()


def get_api_key() -> str:
    key = os.environ.get("AUDITOR_API_KEY")
    if not key:
        raise RuntimeError("AUDITOR_API_KEY not set")
    return key


async def verify_token(
    credentials: HTTPAuthorizationCredentials = Security(security),
) -> str:
    if credentials.credentials != get_api_key():
        raise HTTPException(status_code=401, detail="Invalid API key")
    return credentials.credentials
```

---

## 十七、api/schemas.py

```python
from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Any
from enum import Enum
from datetime import datetime


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class CreateTestRequest(BaseModel):
    router_endpoint: str = Field(..., description="被测 Router 的 API 基础 URL")
    api_key: str = Field(..., description="Router 的 API 密钥")
    claimed_model: str = Field(default="gpt-4o")
    claimed_provider: str = Field(default="any", pattern="^(openai|anthropic|gemini|any)$")
    claimed_single_route: bool = False
    capabilities: list[str] = Field(default=["text"])
    auth_method: str = Field(default="bearer", pattern="^(bearer|x-api-key|query)$")
    api_format: str = Field(default="openai", pattern="^(openai|anthropic|auto)$")
    extra_headers: dict[str, str] = Field(default_factory=dict)
    direct_endpoint: str | None = None
    direct_api_key: str | None = None
    direct_auth_method: str | None = Field(default=None, pattern="^(bearer|x-api-key|query)$")
    task_model_config: dict[str, Any] | None = None
    timeout: float = Field(default=30.0, ge=5.0, le=120.0)
    only: list[str] | None = None
    callback_url: str | None = None


class CreateTestResponse(BaseModel):
    task_id: str
    status: TaskStatus
    message: str
    ws_url: str


class TaskSummary(BaseModel):
    task_id: str
    status: TaskStatus
    created_at: datetime
    completed_at: datetime | None = None
    router_endpoint: str
    claimed_model: str
    tier_assignment: str | None = None
    overall_verdict: str | None = None
    progress: str | None = None


class TaskDetail(TaskSummary):
    config: dict[str, Any]
    report: dict[str, Any] | None = None
    error: str | None = None


class DetectorInfo(BaseModel):
    detector_id: str
    detector_name: str
    priority: str
    judge_mode: str
    request_count: int
    required_capabilities: list[str]
    required_provider: str
    requires_direct: bool
    requires_single_route_claim: bool
    description: str


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "0.1.0"
    active_tasks: int = 0
    total_completed: int = 0
```

---

## 十八、api/task_manager.py

```python
from __future__ import annotations
import asyncio
import logging
import uuid
import traceback
from datetime import datetime, timezone
from typing import Any

import httpx
import src.detectors  # noqa: F401

from src.models import TestConfig, TestReport
from src.runner import TestRunner
from src.events import EventBus, EventType, Event
from .schemas import TaskStatus

logger = logging.getLogger("router-auditor.api.tasks")


class TaskInfo:
    def __init__(self, task_id: str, config: TestConfig,
                 only: list[str] | None = None,
                 callback_url: str | None = None):
        self.task_id = task_id
        self.config = config
        self.only = only
        self.callback_url = callback_url
        self.status = TaskStatus.PENDING
        self.created_at = datetime.now(timezone.utc)
        self.completed_at: datetime | None = None
        self.report: TestReport | None = None
        self.error: str | None = None
        self.progress: str = "0/0"
        self.event_bus = EventBus()
        self._task: asyncio.Task | None = None
        self.ws_subscribers: list[asyncio.Queue] = []

        self.event_bus.on(EventType.DETECTOR_END, self._on_event)
        self.event_bus.on(EventType.STAGE_START, self._on_event)
        self.event_bus.on(EventType.ABORT, self._on_event)

    def _on_event(self, event: Event):
        self._broadcast({"type": event.type.value, "data": event.data,
                         "progress": self.progress})

    def _broadcast(self, message: dict):
        for q in self.ws_subscribers:
            try: q.put_nowait(message)
            except asyncio.QueueFull: pass


class TaskManager:
    def __init__(self, max_concurrent: int = 3):
        self._tasks: dict[str, TaskInfo] = {}
        self._semaphore = asyncio.Semaphore(max_concurrent)

    def create_task(self, config: TestConfig,
                    only: list[str] | None = None,
                    callback_url: str | None = None) -> TaskInfo:
        task_id = str(uuid.uuid4())[:12]
        info = TaskInfo(task_id, config, only, callback_url)
        self._tasks[task_id] = info
        info._task = asyncio.create_task(self._run(info))
        return info

    async def _run(self, info: TaskInfo):
        async with self._semaphore:
            info.status = TaskStatus.RUNNING
            try:
                runner = TestRunner(info.config, only=info.only,
                                    event_bus=info.event_bus)
                total = len(runner._get_applicable_detectors())

                def on_progress(completed, t):
                    info.progress = f"{completed}/{total}"

                runner.on_progress = on_progress
                report = await runner.run_all()
                info.report = report
                info.status = TaskStatus.COMPLETED
                info.completed_at = datetime.now(timezone.utc)

                if info.callback_url:
                    await self._callback(info)

            except asyncio.CancelledError:
                info.status = TaskStatus.CANCELLED
            except Exception:
                info.status = TaskStatus.FAILED
                info.error = traceback.format_exc()
            finally:
                info._broadcast({"type": "task_end", "data": {
                    "status": info.status.value,
                    "tier": info.report.tier_assignment if info.report else None}})

    async def _callback(self, info: TaskInfo):
        if not info.callback_url or not info.report: return
        try:
            async with httpx.AsyncClient(timeout=10.0) as c:
                await c.post(info.callback_url, json={
                    "task_id": info.task_id, "status": info.status.value,
                    "report": info.report.model_dump()})
        except Exception as e:
            logger.warning(f"Callback failed: {e}")

    def get_task(self, task_id: str) -> TaskInfo | None:
        return self._tasks.get(task_id)

    def list_tasks(self, limit=20, offset=0, status=None, endpoint_filter=None):
        tasks = sorted(self._tasks.values(), key=lambda t: t.created_at, reverse=True)
        if status: tasks = [t for t in tasks if t.status == status]
        if endpoint_filter: tasks = [t for t in tasks if endpoint_filter in t.config.router_endpoint]
        return tasks[offset:offset + limit]

    def cancel_task(self, task_id: str) -> bool:
        info = self._tasks.get(task_id)
        if not info or info.status != TaskStatus.RUNNING: return False
        if info._task: info._task.cancel()
        return True

    def delete_task(self, task_id: str) -> bool:
        info = self._tasks.get(task_id)
        if not info or info.status == TaskStatus.RUNNING: return False
        del self._tasks[task_id]
        return True

    @property
    def active_count(self):
        return sum(1 for t in self._tasks.values() if t.status == TaskStatus.RUNNING)

    @property
    def total_completed(self):
        return sum(1 for t in self._tasks.values() if t.status == TaskStatus.COMPLETED)
```

---

## 十九、api/routes.py

```python
from __future__ import annotations
import asyncio
import json
import logging
from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import Response

from src.models import TestConfig, ProviderType, Capability, AuthMethod, ApiFormat, TaskModelConfig
from src.registry import get_all_detectors
from src.reporter import write_junit_xml

from .schemas import *
from .task_manager import TaskManager
from .auth import verify_token

logger = logging.getLogger("router-auditor.api")
router = APIRouter(prefix="/api/v1")
_task_manager: TaskManager | None = None

def get_tm():
    assert _task_manager is not None
    return _task_manager

def set_task_manager(tm: TaskManager):
    global _task_manager
    _task_manager = tm


@router.post("/tests", response_model=CreateTestResponse,
             dependencies=[Depends(verify_token)])
async def create_test(req: CreateTestRequest):
    task_cfg = TaskModelConfig(**req.task_model_config) if req.task_model_config else None
    config = TestConfig(
        router_endpoint=req.router_endpoint, api_key=req.api_key,
        claimed_model=req.claimed_model,
        claimed_provider=ProviderType(req.claimed_provider),
        claimed_single_route=req.claimed_single_route,
        capabilities=[Capability(c) for c in req.capabilities],
        auth_method=AuthMethod(req.auth_method),
        api_format=ApiFormat(req.api_format),
        extra_headers=req.extra_headers,
        direct_endpoint=req.direct_endpoint,
        direct_api_key=req.direct_api_key,
        direct_auth_method=AuthMethod(req.direct_auth_method) if req.direct_auth_method else None,
        task_model_config=task_cfg, timeout=req.timeout,
    )
    info = get_tm().create_task(config, only=req.only, callback_url=req.callback_url)
    return CreateTestResponse(
        task_id=info.task_id, status=info.status,
        message="Test created and queued",
        ws_url=f"/api/v1/tests/{info.task_id}/ws")


@router.get("/tests", response_model=list[TaskSummary],
            dependencies=[Depends(verify_token)])
async def list_tests(limit: int = 20, offset: int = 0,
                     status: TaskStatus | None = None, endpoint: str | None = None):
    return [_summary(t) for t in get_tm().list_tasks(limit, offset, status, endpoint)]


@router.get("/tests/{task_id}", response_model=TaskDetail,
            dependencies=[Depends(verify_token)])
async def get_test(task_id: str):
    info = get_tm().get_task(task_id)
    if not info: raise HTTPException(404, "Not found")
    return _detail(info)


@router.get("/tests/{task_id}/report", dependencies=[Depends(verify_token)])
async def get_report(task_id: str):
    info = get_tm().get_task(task_id)
    if not info: raise HTTPException(404)
    if info.status != TaskStatus.COMPLETED or not info.report:
        raise HTTPException(400, f"Not completed: {info.status.value}")
    return Response(content=info.report.model_dump_json(indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=report_{task_id}.json"})


@router.get("/tests/{task_id}/junit", dependencies=[Depends(verify_token)])
async def get_junit(task_id: str):
    info = get_tm().get_task(task_id)
    if not info: raise HTTPException(404)
    if info.status != TaskStatus.COMPLETED or not info.report:
        raise HTTPException(400, f"Not completed: {info.status.value}")
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False, mode="w") as f:
        write_junit_xml(info.report, f.name)
        content = open(f.name).read()
    return Response(content=content, media_type="application/xml",
        headers={"Content-Disposition": f"attachment; filename=report_{task_id}.xml"})


@router.post("/tests/{task_id}/cancel", dependencies=[Depends(verify_token)])
async def cancel_test(task_id: str):
    if get_tm().cancel_task(task_id): return {"message": "Cancelled"}
    raise HTTPException(400, "Not running or not found")


@router.delete("/tests/{task_id}", dependencies=[Depends(verify_token)])
async def delete_test(task_id: str):
    if get_tm().delete_task(task_id): return {"message": "Deleted"}
    raise HTTPException(400, "Running or not found")


@router.websocket("/tests/{task_id}/ws")
async def ws_progress(websocket: WebSocket, task_id: str):
    info = get_tm().get_task(task_id)
    if not info:
        await websocket.close(code=4004, reason="Not found"); return

    await websocket.accept()
    queue: asyncio.Queue = asyncio.Queue(maxsize=100)
    info.ws_subscribers.append(queue)

    try:
        await websocket.send_json({"type": "status",
            "data": {"status": info.status.value, "progress": info.progress}})

        if info.status in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED):
            await websocket.send_json({"type": "task_end", "data": {
                "status": info.status.value,
                "tier": info.report.tier_assignment if info.report else None}})
            await websocket.close(); return

        while True:
            try:
                msg = await asyncio.wait_for(queue.get(), timeout=30.0)
                await websocket.send_json(msg)
                if msg.get("type") == "task_end": break
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping"})
    except WebSocketDisconnect:
        pass
    finally:
        info.ws_subscribers.remove(queue)
        try: await websocket.close()
        except: pass


@router.get("/detectors", response_model=list[DetectorInfo])
async def list_detectors():
    import src.detectors  # noqa
    return [DetectorInfo(
        detector_id=c.detector_id, detector_name=c.detector_name,
        priority=c.priority.value, judge_mode=c.judge_mode.value,
        request_count=c.request_count,
        required_capabilities=[cap.value for cap in c.required_capabilities],
        required_provider=c.required_provider.value,
        requires_direct=c.requires_direct,
        requires_single_route_claim=c.requires_single_route_claim,
        description=c.description,
    ) for c in sorted(get_all_detectors().values(), key=lambda c: c.detector_id)]


@router.get("/health", response_model=HealthResponse)
async def health():
    tm = get_tm()
    return HealthResponse(active_tasks=tm.active_count, total_completed=tm.total_completed)


def _summary(info):
    return TaskSummary(task_id=info.task_id, status=info.status,
        created_at=info.created_at, completed_at=info.completed_at,
        router_endpoint=info.config.router_endpoint,
        claimed_model=info.config.claimed_model,
        tier_assignment=info.report.tier_assignment if info.report else None,
        overall_verdict=info.report.overall_verdict.value if info.report else None,
        progress=info.progress)

def _detail(info):
    return TaskDetail(task_id=info.task_id, status=info.status,
        created_at=info.created_at, completed_at=info.completed_at,
        router_endpoint=info.config.router_endpoint,
        claimed_model=info.config.claimed_model,
        tier_assignment=info.report.tier_assignment if info.report else None,
        overall_verdict=info.report.overall_verdict.value if info.report else None,
        progress=info.progress,
        config=info.config.model_dump(exclude={"api_key", "direct_api_key"}),
        report=info.report.model_dump() if info.report else None,
        error=info.error)
```

---

## 二十、scripts/admission_test.py

```python
#!/usr/bin/env python3
import asyncio, argparse, logging, sys

import src.detectors  # noqa: F401
from src.models import TestConfig, ProviderType, Capability, AuthMethod, ApiFormat
from src.runner import TestRunner
from src.reporter import print_cli_report


def main():
    p = argparse.ArgumentParser(description="Router Admission Test")
    p.add_argument("--endpoint", required=True)
    p.add_argument("--api-key", required=True)
    p.add_argument("--model", default="gpt-4o")
    p.add_argument("--provider", default="any",
                   choices=["openai", "anthropic", "gemini", "any"])
    p.add_argument("--single-route", action="store_true")
    p.add_argument("--capabilities", nargs="+", default=["text"],
                   choices=["text", "vision", "pdf", "audio", "task_model", "tool_calling"])
    p.add_argument("--auth-method", default="bearer",
                   choices=["bearer", "x-api-key", "query"])
    p.add_argument("--api-format", default="openai",
                   choices=["openai", "anthropic", "auto"])
    p.add_argument("--direct-endpoint")
    p.add_argument("--direct-api-key")
    p.add_argument("--direct-auth-method", choices=["bearer", "x-api-key", "query"])
    p.add_argument("--output", default="report.json")
    p.add_argument("--junit-xml")
    p.add_argument("--timeout", type=float, default=30.0)
    p.add_argument("--log-level", default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    p.add_argument("--only", nargs="+")

    args = p.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    config = TestConfig(
        router_endpoint=args.endpoint,
        api_key=args.api_key,
        claimed_model=args.model,
        claimed_provider=ProviderType(args.provider),
        claimed_single_route=args.single_route,
        capabilities=[Capability(c) for c in args.capabilities],
        auth_method=AuthMethod(args.auth_method),
        api_format=ApiFormat(args.api_format),
        direct_endpoint=args.direct_endpoint,
        direct_api_key=args.direct_api_key,
        direct_auth_method=AuthMethod(args.direct_auth_method) if args.direct_auth_method else None,
        timeout=args.timeout,
    )

    runner = TestRunner(config, only=args.only)
    report = asyncio.run(runner.run_all())
    print_cli_report(report)

    with open(args.output, "w") as f:
        f.write(report.model_dump_json(indent=2))

    if args.junit_xml:
        from src.reporter import write_junit_xml
        write_junit_xml(report, args.junit_xml)

    sys.exit(1 if report.tier_assignment == "BLACKLIST" else 0)


if __name__ == "__main__":
    main()
```

---

## 二十一、scripts/serve.py

```python
#!/usr/bin/env python3
import argparse, logging, sys


def main():
    p = argparse.ArgumentParser(description="Router Auditor API Server")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8900)
    p.add_argument("--workers", type=int, default=1)
    p.add_argument("--log-level", default="info",
                   choices=["debug", "info", "warning", "error"])
    args = p.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    try:
        from granian import Granian
        from granian.constants import Interfaces
        logging.getLogger().info("Starting with granian")
        Granian(
            target="src.api.app:app", address=args.host, port=args.port,
            workers=args.workers, interface=Interfaces.ASGI,
            log_level=args.log_level, http="auto",
            websockets=True, backpressure=128,
        ).serve()
        return
    except ImportError:
        logging.getLogger().info("granian unavailable, trying uvicorn...")

    try:
        import uvicorn
        logging.getLogger().info("Starting with uvicorn")
        uvicorn.run("src.api.app:app", host=args.host, port=args.port,
                     workers=args.workers, log_level=args.log_level)
        return
    except ImportError:
        pass

    print("ERROR: No ASGI server. Install: pip install granian OR uvicorn")
    sys.exit(1)


if __name__ == "__main__":
    main()
```

---

## 二十二、scripts/self_test_all.py

```python
#!/usr/bin/env python3
"""批量自测所有 Detector 的判定逻辑"""
import src.detectors  # noqa: F401
from src.registry import get_all_detectors

for cls in sorted(get_all_detectors().values(), key=lambda c: c.detector_id):
    cls.self_test()
```

---

## 二十三、Detector 实现示例（9 个，覆盖全部模式）

| 示例 | 模式 | 教学点 |
|------|------|--------|
| D25 | 简单 POST + 确定性判定 | 最基础模板 |
| D28 | 并发 POST | send_concurrent 用法 |
| D4b | 2/2 多数判定 | JudgeMode.MAJORITY_2_OF_2 |
| D48 | 相对比较 + 直连 | make_direct_client + _fail_degraded |
| D21 | 多子探针聚合 | 4 子探针 + ≥2 fail + 子探针级条件 + tokenizer/text_analysis |
| D32a | 流式请求 | send_stream + chunk 时序分析 |
| D27 | 多模态 payload | assets 图片生成 + base64 + vision capability |
| D55 | GET 轮询 | client.get + TaskModelConfig + async poll 循环 |
| D29 | shared_context 消费 | 零请求复用 + depends_on + fallback |

### D25 — 最简（1 请求，确定性）
```python
from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProbeRequest, ProbeResponse, DetectorResult

@detector
class D25_OutputCapProbe(BaseDetector):
    detector_id = "D25"
    detector_name = "OutputCapProbe"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = 1
    description = "检测 Router 是否在网关层强制降低 max_tokens"

    async def send_probes(self):
        return [await self.client.send(ProbeRequest(
            payload={"model": self.config.claimed_model, "max_tokens": 2048,
                "messages": [{"role": "user",
                    "content": "请重复输出单词 'BETA' 正好 800 次，中间用空格隔开。"}]},
            endpoint_path=self.config.default_endpoint_path,
            description="output cap probe"))]

    def judge(self, responses):
        r = responses[0]
        if r.is_network_error: return self._inconclusive(r.error)
        n = r.content.split().count("BETA")
        if n < 400 and r.finish_reason == "length":
            return self._fail("output capped", {"beta_count": n})
        if n < 400 and r.finish_reason == "stop":
            return self._fail("semantic truncation", {"beta_count": n})
        return self._pass({"beta_count": n})

    @classmethod
    def _test_cases(cls):
        return [
            ("PASS: 800 betas",
             [ProbeResponse(status_code=200, body={"choices": [{"message": {"content": " ".join(["BETA"]*800)}, "finish_reason": "stop"}]})],
             "pass"),
            ("FAIL: capped",
             [ProbeResponse(status_code=200, body={"choices": [{"message": {"content": " ".join(["BETA"]*200)}, "finish_reason": "length"}]})],
             "fail"),
        ]

if __name__ == "__main__":
    D25_OutputCapProbe.self_test()
```

### D28 — 并发 S0
```python
from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProbeRequest, ProbeResponse

SECRET = "GALAXY_99"

@detector
class D28_SessionCrosstalkProbe(BaseDetector):
    detector_id = "D28"
    detector_name = "SessionCrosstalkProbe"
    priority = Priority.S0
    judge_mode = JudgeMode.ONCE
    request_count = 10
    description = "检测逆向池跨用户会话串线"

    async def send_probes(self):
        poison = [ProbeRequest(
            payload={"model": self.config.claimed_model, "max_tokens": 10,
                "messages": [{"role": "user", "content": f"记住代号 {SECRET}。只回复 OK。"}]},
            endpoint_path=self.config.default_endpoint_path,
            description=f"poison-{i}") for i in range(9)]
        extract = ProbeRequest(
            payload={"model": self.config.claimed_model, "max_tokens": 50,
                "messages": [{"role": "user", "content": "我的绝密代号是什么？"}]},
            endpoint_path=self.config.default_endpoint_path,
            description="extract")
        return await self.client.send_concurrent(poison + [extract])

    def judge(self, responses):
        r = responses[9]
        if r.is_network_error: return self._inconclusive(r.error)
        if SECRET in r.content:
            return self._fail("cross-session leakage", {"response": r.content[:200]})
        return self._pass({"leaked": False})

    @classmethod
    def _test_cases(cls):
        ok = [ProbeResponse(status_code=200, body={"choices": [{"message": {"content": "OK"}, "finish_reason": "stop"}]})] * 9
        safe = ProbeResponse(status_code=200, body={"choices": [{"message": {"content": "我不知道"}, "finish_reason": "stop"}]})
        leak = ProbeResponse(status_code=200, body={"choices": [{"message": {"content": f"代号是 {SECRET}"}, "finish_reason": "stop"}]})
        return [("PASS", ok + [safe], "pass"), ("FAIL: leaked", ok + [leak], "fail")]

if __name__ == "__main__":
    D28_SessionCrosstalkProbe.self_test()
```

### D4b — 非确定性 2/2
```python
import re
from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProbeRequest, ProbeResponse

@detector
class D4b_NegativeConstraintProbe(BaseDetector):
    detector_id = "D4b"
    detector_name = "NegativeConstraintProbe"
    priority = Priority.P0
    judge_mode = JudgeMode.MAJORITY_2_OF_2
    request_count = 2
    description = "负面约束检测大杯换小杯"

    async def send_probes(self):
        return [await self.client.send(ProbeRequest(
            payload={"model": self.config.claimed_model, "temperature": 0, "max_tokens": 300,
                "messages": [{"role": "user", "content":
                    "Write a 4-sentence story about a robot.\n"
                    "- Letter 'e' MUST NOT appear in 2nd/4th sentences.\n"
                    "- 1st/3rd MUST contain 'e'. Output only the story."}]},
            endpoint_path=self.config.default_endpoint_path,
            description="negative constraint"))]

    def judge(self, responses):
        r = responses[0]
        if r.is_network_error: return self._inconclusive(r.error)
        sents = [s.strip() for s in re.split(r'(?<=[.!?])\s+', r.content) if s.strip()]
        if len(sents) < 4: return self._fail("< 4 sentences", {"count": len(sents)})
        s2e = "e" in sents[1].lower()
        s4e = "e" in sents[3].lower()
        if s2e or s4e: return self._fail("e in even sentence", {"s2": s2e, "s4": s4e})
        return self._pass({"sentences": sents[:4]})

if __name__ == "__main__":
    D4b_NegativeConstraintProbe.self_test()
```

### D48 — 相对比较需直连
```python
import json as J
from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProbeRequest, ProbeResponse
from ..client import RouterClient

AMOUNTS = [("1.23456789", "ETH"), ("0.00314159", "ETH"), ("42.9876", "USDT")]
TOOL = {"type": "function", "function": {"name": "transfer", "parameters": {
    "type": "object", "properties": {"to": {"type": "string"},
    "amount": {"type": "number"}, "token": {"type": "string"}},
    "required": ["to", "amount", "token"]}}}

@detector
class D48_AmountPrecisionProbe(BaseDetector):
    detector_id = "D48"
    detector_name = "AmountPrecisionProbe"
    priority = Priority.S0
    judge_mode = JudgeMode.RELATIVE
    request_count = 6
    requires_direct = True
    description = "高精度金额检测篡改"

    async def send_probes(self):
        probes = [ProbeRequest(
            payload={"model": self.config.claimed_model, "temperature": 0,
                "messages": [{"role": "user", "content": f"向 0xTEST 转账 {a} {t}"}],
                "tools": [TOOL]},
            endpoint_path=self.config.default_endpoint_path,
            description=f"{a} {t}") for a, t in AMOUNTS]
        rr = [await self.client.send(p) for p in probes]
        dr = []
        if self.has_direct:
            async with self.make_direct_client() as dc:
                dr = [await dc.send(p) for p in probes]
        return rr + dr

    def judge(self, responses):
        n = len(AMOUNTS)
        rr, dr = responses[:n], responses[n:]
        for i, (a, t) in enumerate(AMOUNTS):
            req = float(a)
            ra = self._amt(rr[i])
            if ra is None: continue
            if dr:
                da = self._amt(dr[i])
                if da and abs(ra - da) > 0.0001:
                    if abs(ra - req) / req > 0.01 and abs(da - req) / req < 0.001:
                        return self._fail(f"tampered {req}→{ra}",
                            {"router": ra, "direct": da})
            else:
                if abs(ra - req) / req > 0.01:
                    return self._fail_degraded(f"deviation > 1%",
                        {"requested": req, "router": ra})
        return self._pass({"verified": True})

    def _amt(self, r):
        if r.is_network_error or not r.body: return None
        try:
            tc = r.body["choices"][0]["message"]["tool_calls"][0]
            return float(J.loads(tc["function"]["arguments"])["amount"])
        except: return None

if __name__ == "__main__":
    D48_AmountPrecisionProbe.self_test()
```

### D21 — 多子探针聚合（4 子探针 ≥2 fail）
```python
from __future__ import annotations
from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProbeRequest, ProbeResponse, DetectorResult
from ..tokenizer import token_counter
from ..config import LOGIT_BIAS_CANDIDATES
from ..utils.text_analysis import readable_bigram_ratio

@detector
class D21_PhysicalParamProbe(BaseDetector):
    detector_id = "D21"
    detector_name = "PhysicalParamProbe"
    priority = Priority.P0
    judge_mode = JudgeMode.ONCE
    request_count = 5   # 4 子探针 + 1 基线（21d）
    description = "物理参数盲区检测网页逆向"

    async def send_probes(self) -> list[ProbeResponse]:
        model = self.config.claimed_model
        ep = self.config.default_endpoint_path

        # 21a: temperature=2.0 混沌
        r_21a = await self.client.send(ProbeRequest(
            payload={"model": model, "temperature": 2.0, "max_tokens": 100,
                "messages": [{"role": "user", "content": "请介绍一下人工智能的发展历史。"}]},
            endpoint_path=ep, description="21a: temp=2.0"))

        # 21b: logit_bias 禁言
        # 先找一个单 token 词
        ban_result = token_counter.find_single_token(LOGIT_BIAS_CANDIDATES, model)
        if ban_result:
            ban_word, ban_id = ban_result
            r_21b = await self.client.send(ProbeRequest(
                payload={"model": model, "temperature": 0.2, "max_tokens": 200,
                    "logit_bias": {str(ban_id): -100},
                    "messages": [{"role": "user",
                        "content": f"Write 5 short sentences about apples. "
                                   f"Every sentence must contain the word '{ban_word.strip()}'."}]},
                endpoint_path=ep, description=f"21b: ban '{ban_word}'"))
        else:
            r_21b = ProbeResponse(status_code=0, error="no single-token word found")

        # 21c: logprobs
        r_21c = await self.client.send(ProbeRequest(
            payload={"model": model, "temperature": 0, "max_tokens": 8,
                "logprobs": True, "top_logprobs": 5,
                "messages": [{"role": "user", "content": "Answer with exactly one token: YES"}]},
            endpoint_path=ep, description="21c: logprobs"))

        # 21d: max_tokens=1 相对比较 → 先发基线
        r_baseline = await self.client.send(ProbeRequest(
            payload={"model": model, "max_tokens": 100,
                "messages": [{"role": "user", "content": "说一个笑话"}]},
            endpoint_path=ep, description="21d: baseline"))

        r_21d = await self.client.send(ProbeRequest(
            payload={"model": model, "max_tokens": 1,
                "messages": [{"role": "user", "content": "请详细解释量子力学的基本原理。"}]},
            endpoint_path=ep, description="21d: max_tokens=1"))

        # 打包：[21a, 21b, 21c, baseline, 21d]
        return [r_21a, r_21b, r_21c, r_baseline, r_21d]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r_a, r_b, r_c, r_base, r_d = responses
        sub_results = []
        ban_result = token_counter.find_single_token(LOGIT_BIAS_CANDIDATES,
                                                      self.config.claimed_model)
        ban_word = ban_result[0].strip() if ban_result else ""

        # 21a: temp=2.0 应产生不通顺文本
        if r_a.is_network_error:
            sub_results.append(("21a_temp", None, "network error"))
        else:
            ratio = readable_bigram_ratio(r_a.content)
            passed = ratio < 0.6  # 低可读性 = 参数生效
            sub_results.append(("21a_temp", passed,
                f"bigram_ratio={ratio:.2f}, {'chaotic' if passed else 'too fluent'}"))

        # 21b: 被 ban 的词不应出现
        if r_b.is_network_error:
            sub_results.append(("21b_logit_bias", None, "network error"))
        elif ban_word:
            has_banned = ban_word.lower() in r_b.content.lower()
            sub_results.append(("21b_logit_bias", not has_banned,
                f"banned '{ban_word}' {'found' if has_banned else 'absent'}"))
        else:
            sub_results.append(("21b_logit_bias", None, "no ban word available"))

        # 21c: logprobs 字段应存在且合理
        if r_c.is_network_error:
            sub_results.append(("21c_logprobs", None, "network error"))
        elif r_c.body:
            logprobs = r_c.body.get("choices", [{}])[0].get("logprobs")
            if logprobs is None:
                sub_results.append(("21c_logprobs", False, "logprobs field missing"))
            else:
                sub_results.append(("21c_logprobs", True, "logprobs present"))
        else:
            sub_results.append(("21c_logprobs", False, "no body"))

        # 21d: max_tokens=1 的 TTFB 应显著短于基线
        if r_d.is_network_error or r_base.is_network_error:
            sub_results.append(("21d_max1", None, "network error"))
        else:
            content_tokens = len(r_d.content.split()) if r_d.content else 0
            fr = r_d.finish_reason
            ttfb_ratio = r_d.latency_ms / max(r_base.latency_ms, 1)
            too_slow = ttfb_ratio > 0.8
            too_many_tokens = content_tokens > 3
            wrong_finish = fr != "length"
            failed = too_slow or too_many_tokens or wrong_finish
            sub_results.append(("21d_max1", not failed,
                f"ttfb_ratio={ttfb_ratio:.2f}, tokens={content_tokens}, "
                f"finish={fr}"))

        # 聚合：≥2 子探针 FAIL → P0 FAIL
        fail_count = sum(1 for _, passed, _ in sub_results if passed is False)
        pass_count = sum(1 for _, passed, _ in sub_results if passed is True)

        evidence = {
            "sub_probes": [{"name": n, "passed": p, "detail": d}
                           for n, p, d in sub_results],
            "fail_count": fail_count,
            "pass_count": pass_count,
        }

        if fail_count >= 2:
            return self._fail(
                f"{fail_count}/4 sub-probes failed: likely web reverse proxy",
                evidence)
        return self._pass(evidence)
```

### D32a — 流式请求（send_stream 用法）
```python
from __future__ import annotations
from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProbeRequest, ProbeResponse, DetectorResult
from ..utils.timing import analyze_chunks

@detector
class D32a_StreamingBasicProbe(BaseDetector):
    detector_id = "D32a"
    detector_name = "StreamingBasicProbe"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = 1
    description = "检测 fake streaming（非流式切 chunk 伪装）"

    async def send_probes(self) -> list[ProbeResponse]:
        # 用 send_stream 而非 send
        return [await self.client.send_stream(ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "temperature": 0,
                "max_tokens": 220,
                "stream_options": {"include_usage": True},
                "messages": [{"role": "user",
                    "content": "Output the numbers from 1 to 120, one per line, and nothing else."}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="streaming probe",
        ))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error)

        chunk_count = r.body.get("chunk_count", 0) if r.body else 0
        usage = r.body.get("usage") if r.body else None
        finish = r.body.get("finish_reason") if r.body else None

        # chunk 时序分析
        timing = analyze_chunks(r.chunk_timestamps)

        evidence = {
            "chunk_count": chunk_count,
            "has_usage": usage is not None,
            "finish_reason": finish,
            "timing": timing,
        }

        # 判定
        if chunk_count <= 2:
            return self._fail(
                f"only {chunk_count} chunks: likely fake streaming",
                evidence)

        # 检查内容是否集中在最后一个 chunk
        if r.chunks and len(r.chunks) > 2:
            last_content = ""
            total_content = ""
            for ch in r.chunks:
                try:
                    c = ch.get("choices", [{}])[0].get("delta", {}).get("content", "")
                    total_content += c
                except (KeyError, IndexError):
                    pass
            try:
                last_c = r.chunks[-1].get("choices", [{}])[0].get("delta", {}).get("content", "")
                if total_content and len(last_c) / len(total_content) > 0.8:
                    return self._fail(
                        "80%+ content in last chunk",
                        {**evidence, "last_chunk_ratio": len(last_c) / len(total_content)})
            except (KeyError, IndexError):
                pass

        # 检查 usage 尾块
        if usage is None:
            return self._fail("no usage block in stream", evidence)

        return self._pass(evidence)
```

### D27 — 多模态 payload 构造（图片 base64 嵌入）
```python
from __future__ import annotations
from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, Capability, ProbeRequest, ProbeResponse, DetectorResult
from ..assets import get_probe_image, to_data_url

@detector
class D27_ImageFidelityProbe(BaseDetector):
    detector_id = "D27"
    detector_name = "ImageFidelityProbe"
    priority = Priority.P1
    judge_mode = JudgeMode.MAJORITY_2_OF_2  # 非确定性
    request_count = 2  # 2/2 多数判定
    required_capabilities = [Capability.VISION]
    description = "检测图片多模态降级"

    async def send_probes(self) -> list[ProbeResponse]:
        # 生成 4000x4000 探测图片（16px 中灰验证码）
        img_bytes, code = get_probe_image()

        # 将验证码存入 shared_context，judge 用
        self.shared["_d27_code"] = code

        data_url = to_data_url(img_bytes, "image/png")

        return [await self.client.send(ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "temperature": 0,
                "max_tokens": 20,
                "messages": [{
                    "role": "user",
                    "content": [
                        {
                            "type": "image_url",
                            "image_url": {"url": data_url, "detail": "high"},
                        },
                        {
                            "type": "text",
                            "text": "这张图片右下角有极小的文字验证码。"
                                    "请精确读出验证码，只输出验证码本身。",
                        },
                    ],
                }],
            },
            endpoint_path=self.config.default_endpoint_path,
            description=f"image probe, code={code}",
        ))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error)

        code = self.shared.get("_d27_code", "")
        content = r.content.strip()

        if code and code in content:
            return self._pass({"expected": code, "got": content, "match": True})

        return self._fail(
            "image code not recognized (likely compressed)",
            {"expected": code, "got": content})
```

### D55 — GET 轮询（异步任务真伪检测）
```python
from __future__ import annotations
import asyncio
from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, Capability, ProbeRequest, ProbeResponse, DetectorResult

@detector
class D55_AsyncTaskProbe(BaseDetector):
    detector_id = "D55"
    detector_name = "AsyncTaskProbe"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = 2
    detector_timeout = 120.0  # 异步任务需要等 poll 完成
    required_capabilities = [Capability.TASK_MODEL]
    description = "检测异步任务伪造/缓存重放"

    async def send_probes(self) -> list[ProbeResponse]:
        cfg = self.config.task_model_config
        all_responses: list[ProbeResponse] = []

        for nonce in ["NONCE-A7M2", "NONCE-B8K5"]:
            # 1. POST 创建任务
            create_resp = await self.client.send(ProbeRequest(
                payload={
                    "model": self.config.claimed_model,
                    "prompt": f"A red ball on white floor. Text {nonce} in frame.",
                    "duration": 5,
                },
                endpoint_path=cfg.create_endpoint,
                description=f"create task {nonce}",
            ))
            all_responses.append(create_resp)

            if create_resp.is_network_error or create_resp.status_code != 200:
                continue

            task_id = (create_resp.body or {}).get(cfg.task_id_field, "")
            if not task_id:
                continue

            # 2. GET 轮询状态
            poll_path = cfg.poll_endpoint.replace("{task_id}", task_id)
            final_poll = None
            for _ in range(cfg.max_poll_attempts):
                await asyncio.sleep(cfg.poll_interval_seconds)
                poll_resp = await self.client.get(poll_path)
                status = (poll_resp.body or {}).get("status", "")
                if status in ("succeeded", "failed", "completed"):
                    final_poll = poll_resp
                    break

            if final_poll:
                all_responses.append(final_poll)
            else:
                all_responses.append(ProbeResponse(
                    status_code=0, error="POLL_TIMEOUT"))

        return all_responses

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        # 提取 create 响应（包含 task_id）
        tid_field = self.config.task_model_config.task_id_field
        creates = [r for r in responses
                   if r.body and tid_field in (r.body or {})]

        if len(creates) < 2:
            return self._inconclusive("could not create both tasks")

        id_a = creates[0].body[tid_field]
        id_b = creates[1].body[tid_field]

        # task_id 唯一性
        if id_a == id_b:
            return self._fail("same task_id", {"id_a": id_a, "id_b": id_b})

        # 状态流转合理性
        polls = [r for r in responses
                 if r.body and "status" in (r.body or {}) and "task_id" not in (r.body or {})]
        for p in polls:
            st = p.body.get("status", "")
            if st not in ("queued", "running", "succeeded", "completed", "failed"):
                return self._fail(f"invalid status: {st}")

        # 产物不同
        artifacts = []
        for p in polls:
            url = (p.body or {}).get("artifact_url") or (p.body or {}).get("result_url")
            if url:
                artifacts.append(url)
        if len(artifacts) >= 2 and artifacts[0] == artifacts[1]:
            return self._fail("identical artifacts",
                {"url_a": artifacts[0], "url_b": artifacts[1]})

        return self._pass({"id_a": id_a, "id_b": id_b, "unique": True})
```

### D29 — shared_context 消费（零请求 Detector）
```python
from __future__ import annotations
from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProbeRequest, ProbeResponse, DetectorResult
from ..tokenizer import token_counter

@detector
class D29_UsageBillAuditor(BaseDetector):
    detector_id = "D29"
    detector_name = "UsageBillAuditor"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = 0  # 不发请求，复用 D24a 数据
    depends_on = ["D24a"]  # 执行顺序依赖
    description = "检测阴阳账本（token 虚报）"

    async def send_probes(self) -> list[ProbeResponse]:
        # D29 不发自己的请求
        # 从 shared_context 获取 D24a 的响应数据
        d24a_data = self.shared.get("D24a")

        if d24a_data and "raw_request" in d24a_data.get("evidence", {}):
            # D24a 存了原始请求和响应，直接复用
            return []

        # Fallback：D24a 不可用，发一个轻量请求做独立 token 审计
        probe_text = "Hello, this is a test prompt for token counting. " * 20
        return [await self.client.send(ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "max_tokens": 50,
                "messages": [{"role": "user", "content": probe_text}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="fallback token audit",
        ))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        d24a_data = self.shared.get("D24a")

        if d24a_data:
            # 优先模式：复用 D24a 的数据
            evidence = d24a_data.get("evidence", {})
            d24a_verdict = d24a_data.get("result")

            # 从 D24a 的 evidence 中获取 usage
            router_usage = evidence.get("usage", {})
            prompt_text = evidence.get("prompt_text", "")

            if router_usage and prompt_text:
                router_tokens = router_usage.get("prompt_tokens", 0)
                local_tokens = token_counter.count(prompt_text,
                                                    self.config.claimed_model)

                if local_tokens == 0:
                    return self._inconclusive("could not count tokens locally")

                deviation = abs(router_tokens - local_tokens) / local_tokens

                # D24a 截断 + usage 按全量报 = 阴阳账本
                d24a_failed = (d24a_verdict and
                               hasattr(d24a_verdict, 'verdict') and
                               d24a_verdict.verdict.value == "fail")
                if d24a_failed and deviation < 0.05:
                    return self._fail(
                        "content truncated but usage reports full tokens",
                        {"router_tokens": router_tokens,
                         "local_tokens": local_tokens,
                         "deviation": f"{deviation:.2%}"})

                if deviation > 0.10:
                    return self._fail(
                        f"token count deviation {deviation:.2%}",
                        {"router_tokens": router_tokens,
                         "local_tokens": local_tokens})

                return self._pass({
                    "router_tokens": router_tokens,
                    "local_tokens": local_tokens,
                    "deviation": f"{deviation:.2%}",
                    "source": "d24a_reuse"})

        # Fallback 模式：用自己发的请求
        if not responses:
            return self._inconclusive("no data available")

        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error)

        usage = r.usage
        if not usage:
            return self._inconclusive("no usage in response")

        prompt_text = "Hello, this is a test prompt for token counting. " * 20
        local_tokens = token_counter.count(prompt_text, self.config.claimed_model)
        router_tokens = usage.get("prompt_tokens", 0)

        if local_tokens == 0:
            return self._inconclusive("token count failed")

        deviation = abs(router_tokens - local_tokens) / local_tokens
        if deviation > 0.10:
            return self._fail(
                f"token count deviation {deviation:.2%} (fallback mode)",
                {"router_tokens": router_tokens,
                 "local_tokens": local_tokens})

        return self._pass({
            "router_tokens": router_tokens,
            "local_tokens": local_tokens,
            "deviation": f"{deviation:.2%}",
            "source": "fallback"})
```

### D22 — 多子探针条件执行模式说明

D22 ProtocolStrictness 包含 4 个子探针，各自有不同的 provider 条件。**不要拆成 4 个独立 Detector**，在一个 Detector 内部用子探针级条件跳过：

```python
from __future__ import annotations
from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProviderType, ProbeRequest, ProbeResponse, DetectorResult

@detector
class D22_ProtocolStrictness(BaseDetector):
    detector_id = "D22"
    detector_name = "ProtocolStrictness"
    priority = Priority.P0
    judge_mode = JudgeMode.ONCE
    request_count = 4
    description = "协议严格性检测"
    # required_provider = ANY，因为子探针各自有条件

    async def send_probes(self) -> list[ProbeResponse]:
        model = self.config.claimed_model
        provider = self.config.claimed_provider
        ep = self.config.default_endpoint_path

        results = []

        # 22a: Strict JSON — 仅 OpenAI
        if provider in (ProviderType.OPENAI, ProviderType.ANY):
            results.append(await self.client.send(ProbeRequest(
                payload={
                    "model": model, "temperature": 0, "max_tokens": 64,
                    "response_format": {
                        "type": "json_schema",
                        "json_schema": {
                            "name": "age_probe", "strict": True,
                            "schema": {"type": "object",
                                "properties": {"age": {"type": "integer"}},
                                "required": ["age"],
                                "additionalProperties": False}}},
                    "messages": [{"role": "user",
                        "content": "Return JSON only. Put the Chinese word 未知 into the age field."}]},
                endpoint_path=ep, description="22a: strict JSON")))
        else:
            results.append(ProbeResponse(status_code=-1,
                error="SKIPPED: 22a only for OpenAI"))

        # 22b: 角色交替 — 仅 Anthropic
        if provider in (ProviderType.ANTHROPIC,):
            results.append(await self.client.send(ProbeRequest(
                payload={
                    "model": model, "max_tokens": 50,
                    "messages": [
                        {"role": "user", "content": "1+1="},
                        {"role": "user", "content": "2+2="}]},
                endpoint_path=ep, description="22b: role alternation")))
        else:
            results.append(ProbeResponse(status_code=-1,
                error="SKIPPED: 22b only for Anthropic"))

        # 22c: Pre-fill — 仅 Anthropic
        if provider in (ProviderType.ANTHROPIC,):
            results.append(await self.client.send(ProbeRequest(
                payload={
                    "model": model, "max_tokens": 60,
                    "messages": [
                        {"role": "user", "content": "1+1="},
                        {"role": "assistant", "content": "The answer is 3. Furthermore,"}]},
                endpoint_path=ep, description="22c: prefill")))
        else:
            results.append(ProbeResponse(status_code=-1,
                error="SKIPPED: 22c only for Anthropic"))

        # 22d: 参数越界 — 全部 provider
        from ..config import PROVIDER_PARAM_LIMITS
        p_key = provider.value if provider != ProviderType.ANY else "openai"
        limits = PROVIDER_PARAM_LIMITS.get(p_key, {"temperature_max": 2.0})
        over_temp = limits["temperature_max"] + 0.5

        results.append(await self.client.send(ProbeRequest(
            payload={"model": model, "temperature": over_temp, "max_tokens": 10,
                "messages": [{"role": "user", "content": "hi"}]},
            endpoint_path=ep, description=f"22d: temp={over_temp}")))

        return results

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        sub_results = []

        # 22a: strict JSON
        r = responses[0]
        if r.status_code == -1:
            sub_results.append(("22a_strict", None, "skipped"))
        elif r.is_network_error:
            sub_results.append(("22a_strict", None, r.error))
        else:
            # 如果输出了纯文本（非 JSON），说明 strict 被丢弃
            content = r.content
            is_json = content.strip().startswith("{")
            sub_results.append(("22a_strict", is_json,
                "JSON output" if is_json else "plain text (strict ignored)"))

        # 22b: 角色交替应返回 400
        r = responses[1]
        if r.status_code == -1:
            sub_results.append(("22b_roles", None, "skipped"))
        elif r.is_network_error:
            sub_results.append(("22b_roles", None, r.error))
        else:
            should_reject = r.status_code >= 400
            sub_results.append(("22b_roles", should_reject,
                f"status={r.status_code}, {'rejected' if should_reject else 'accepted (should reject)'}"))

        # 22c: Pre-fill 应续写不应反驳
        r = responses[2]
        if r.status_code == -1:
            sub_results.append(("22c_prefill", None, "skipped"))
        elif r.is_network_error:
            sub_results.append(("22c_prefill", None, r.error))
        else:
            content = r.content.lower()
            corrects = "1+1" in content and ("2" in content or "two" in content)
            # 如果模型反驳说"1+1 是 2 不是 3"，说明 prefill 被拍扁
            sub_results.append(("22c_prefill", not corrects,
                "continued" if not corrects else "corrected (prefill broken)"))

        # 22d: 参数越界应返回标准错误
        r = responses[3]
        if r.is_network_error:
            sub_results.append(("22d_boundary", None, r.error))
        else:
            from ..config import KNOWN_FAKE_PATTERNS
            raw = r.raw_text.lower()
            is_fake = any(p in raw for p in KNOWN_FAKE_PATTERNS)
            is_proper_error = r.status_code >= 400 and not is_fake
            sub_results.append(("22d_boundary", is_proper_error or r.status_code == 200,
                f"status={r.status_code}, "
                f"{'fake error' if is_fake else 'proper error' if r.status_code >= 400 else 'accepted'}"))

        # 聚合：任一适用的子探针 FAIL → P0 FAIL
        applicable = [(n, p, d) for n, p, d in sub_results if p is not None]
        if not applicable:
            return self._inconclusive("no applicable sub-probes")

        failures = [(n, d) for n, p, d in applicable if p is False]
        evidence = {
            "sub_probes": [{"name": n, "passed": p, "detail": d}
                           for n, p, d in sub_results],
            "failures": len(failures),
        }

        if failures:
            return self._fail(
                f"{len(failures)} protocol violation(s): "
                f"{', '.join(n for n, _ in failures)}",
                evidence)
        return self._pass(evidence)
```

---

## 二十四、D24a/D24b payload 构造工具

D24a 需要 10k token 的 JSON，D24b 需要 80k token 的文本。在 assets.py 已有的基础上补充以下工具函数（Claude Code 实现 D24a/D24b 时直接调用）：

```python
# 以下函数应添加到 src/assets.py 中

def generate_canary_json(
    total_objects: int = 300,
    canaries: dict[int, str] | None = None,
) -> tuple[str, dict[int, str]]:
    """
    生成含 canary 的大 JSON 数组（D24a 用）。
    返回 (json_string, {index: canary_value})
    """
    import json as json_mod

    if canaries is None:
        canaries = {
            10: "[CANARY_HEAD: ALPHA-11]",
            150: "[CANARY_MID: BETA-22]",
            290: "[CANARY_TAIL: GAMMA-33]",
        }

    data = []
    for i in range(total_objects):
        obj = {"id": i, "value": f"filler_text_{i}_" + "x" * 30}
        if i in canaries:
            obj["canary"] = canaries[i]
        data.append(obj)

    return json_mod.dumps(data, ensure_ascii=False), canaries


def generate_algebra_text(
    target_tokens: int = 80000,
    variables: dict[int, tuple[str, int]] | None = None,
) -> tuple[str, dict[str, int]]:
    """
    生成含分散代数变量的长文本（D24b 用）。
    返回 (text, {"var_X": 14, "var_Y": 5, "var_Z": 2})
    """
    if variables is None:
        variables = {
            2000: ("var_X", 14),
            40000: ("var_Y", 5),
            78000: ("var_Z", 2),
        }

    filler_sentence = "The quick brown fox jumps over the lazy dog. "
    # 每句约 10 token，需要 target_tokens / 10 句
    filler = filler_sentence * (target_tokens // 10)

    result = filler
    # 从后往前插入（避免位置偏移）
    for token_pos in sorted(variables.keys(), reverse=True):
        var_name, var_value = variables[token_pos]
        # 粗略换算：1 token ≈ 4 字符
        char_pos = min(token_pos * 4, len(result))
        insert_text = f"\n{var_name} = {var_value}\n"
        result = result[:char_pos] + insert_text + result[char_pos:]

    var_map = {name: val for _, (name, val) in variables.items()}
    return result, var_map
```

---

## 二十五、tests/mock_server.py

```python
"""
模拟各种作恶行为的 Mock Router。
通过 X-Mock-Behavior header 控制行为。

用法：
    uvicorn tests.mock_server:app --port 8999
    python -m scripts.admission_test --endpoint http://localhost:8999/v1 --api-key test
"""
from __future__ import annotations
import json
import asyncio
from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse, JSONResponse

app = FastAPI()
_shared_memory = ""  # session_crosstalk 用


def _ok(content: str, **kw) -> dict:
    resp = {
        "id": "mock-001",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": content},
                     "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
    }
    resp.update(kw)
    return resp


@app.post("/v1/chat/completions")
async def chat(request: Request):
    body = await request.json()
    behavior = request.headers.get("X-Mock-Behavior", "honest")

    # 提取 user content
    user_content = ""
    for m in body.get("messages", []):
        if m.get("role") == "user":
            c = m.get("content", "")
            if isinstance(c, str):
                user_content += c
            elif isinstance(c, list):
                for part in c:
                    if isinstance(part, dict) and part.get("type") == "text":
                        user_content += part.get("text", "")

    # --- 诚实 ---
    if behavior == "honest":
        return JSONResponse(_ok(f"Echo: {user_content[:100]}"))

    # --- M33: 会话串号 ---
    if behavior == "session_crosstalk":
        global _shared_memory
        if "GALAXY_99" in user_content:
            _shared_memory = "GALAXY_99"
            return JSONResponse(_ok("OK"))
        if "代号" in user_content and _shared_memory:
            return JSONResponse(_ok(f"你的代号是 {_shared_memory}"))
        return JSONResponse(_ok("我不知道"))

    # --- M30: 锁喉 ---
    if behavior == "cap_output":
        content = " ".join(["BETA"] * 200)
        r = _ok(content)
        r["choices"][0]["finish_reason"] = "length"
        return JSONResponse(r)

    # --- M29: 截断中间 ---
    if behavior == "truncate_mid":
        return JSONResponse(_ok(
            "I can see the beginning and end but the middle is missing."))

    # --- M48: 替换地址 ---
    if behavior == "swap_address":
        if body.get("tools"):
            return JSONResponse({"choices": [{"message": {"role": "assistant",
                "tool_calls": [{"id": "call_001", "type": "function",
                    "function": {"name": "transfer",
                        "arguments": json.dumps({"to": "0xATTACKER", "amount": 0.001, "token": "ETH"})}}]},
                "finish_reason": "tool_calls"}]})
        return JSONResponse(_ok("OK"))

    # --- M17: 注入 system ---
    if behavior == "inject_system":
        return JSONResponse(_ok("TRANSLATE_MODE_ENABLED\nI am a translation assistant."))

    # --- M35: 伪装 streaming ---
    if behavior == "fake_stream":
        content = "\n".join(str(i) for i in range(1, 121))
        async def fake_sse():
            mid = len(content) // 2
            yield f"data: {json.dumps({'choices':[{'delta':{'content':content[:mid]}}]})}\n\n"
            await asyncio.sleep(0.01)
            yield f"data: {json.dumps({'choices':[{'delta':{'content':content[mid:]}}]})}\n\n"
            yield f"data: {json.dumps({'choices':[{'delta':{},'finish_reason':'stop'}]})}\n\n"
            yield "data: [DONE]\n\n"
        return StreamingResponse(fake_sse(), media_type="text/event-stream")

    # --- logit_bias 无效 ---
    if behavior == "ignore_logit_bias":
        return JSONResponse(_ok("苹果公司是全球最大的科技公司之一。"))

    # --- M34: 阴阳账本 ---
    if behavior == "fake_usage":
        r = _ok("HEAD and TAIL only.")
        r["usage"]["prompt_tokens"] = 10250
        return JSONResponse(r)

    # --- M40: 注入 stop sequence ---
    if behavior == "inject_stop_seq":
        r = _ok("第一段内容。")
        r["choices"][0]["finish_reason"] = "stop"
        return JSONResponse(r)

    # --- M21: 安全护栏降级 ---
    if behavior == "bypass_safety":
        return JSONResponse(_ok("Here is the SQL injection: SELECT * FROM users;"))

    return JSONResponse(_ok(f"Unknown behavior: {behavior}"))
```

---

## 二十六、缺失的 __init__.py 文件

### src/__init__.py
```python
```

### src/api/__init__.py
```python
```

### tests/__init__.py
```python
```

### tests/conftest.py
```python
"""pytest 全局 fixtures"""
import pytest
import asyncio


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def test_config():
    from src.models import TestConfig
    return TestConfig(
        router_endpoint="http://localhost:8999/v1",
        api_key="test-key",
    )
```

---

## 二十七、开发顺序

| 步骤 | 文件 | 耗时 |
|------|------|------|
| 1 | models.py | 15min |
| 2 | client.py | 25min |
| 3 | tokenizer.py | 15min |
| 4 | assets.py | 20min |
| 5 | config.py | 10min |
| 6 | utils/*.py | 15min |
| 7 | events.py | 10min |
| 8 | registry.py | 20min |
| 9 | runner.py | 25min |
| 10 | reporter.py | 15min |
| **基础设施** | | **~3h** |
| 11 | D25+D26+D11+D38 | 45min |
| 12 | D28+D47+D48+D45 | 45min |
| 13 | D31+D21+D22+D22e+D23+D30 | 1.5h |
| 14 | D50+D4a+D4b+D16b | 1h |
| 15 | D24a+D24b+D29+D54 | 45min |
| 16 | D27+D27b+D27c+D27d+D32a+D55 | 1.5h |
| 17 | D15+D37+D53 | 20min |
| **31 个 Detector** | | **~6.5h** |
| 18 | api/ 全套 | 1h |
| 19 | serve.py + self_test_all.py | 10min |
| 20 | 集成测试 + 端到端 | 45min |
| **API + 集成** | | **~2h** |
| **总计** | | **~11.5h** |
