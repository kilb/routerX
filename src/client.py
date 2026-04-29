"""HTTP client for Router Auditor.

Supports POST / GET / SSE with multiple auth methods. Enforces rate limiting
via a semaphore + min-interval throttle, retries 429 using Retry-After, and
converts every error path into a ``ProbeResponse`` with ``status_code == 0``
so ``judge()`` can treat it uniformly.
"""
from __future__ import annotations

import asyncio
import json
import logging
import random
import re
import time
import uuid

import httpx
from httpx_sse import aconnect_sse

from .events import Event, EventBus, EventType
from .models import AuthMethod, ProbeRequest, ProbeResponse

logger = logging.getLogger("router-auditor.client")

_MAX_RETRIES = 3
_CONNECT_TIMEOUT = 10.0
_TIMEOUT_BACKOFF_BASE = 1.0  # seconds; doubled each retry with a little jitter

# Redact ``api_key=...`` anywhere it appears in an error message (QUERY auth).
_API_KEY_IN_URL = re.compile(
    r"((?:api_?key|token|access_token|secret)=)[^&\s'\"]+", re.IGNORECASE,
)


def _sanitize(msg: str) -> str:
    return _API_KEY_IN_URL.sub(r"\1***", msg)


def _timeout_backoff(attempt: int) -> float:
    """Exponential backoff with +/-20% jitter: 1s, 2s, 4s, ..."""
    base = _TIMEOUT_BACKOFF_BASE * (2 ** attempt)
    return base * (1.0 + (random.random() - 0.5) * 0.4)


class RouterClient:
    def __init__(
        self,
        endpoint: str,
        api_key: str,
        auth_method: AuthMethod = AuthMethod.BEARER,
        extra_headers: dict[str, str] | None = None,
        timeout: float = 60.0,
        max_concurrent: int = 5,
        min_interval: float = 0.1,
        event_bus: EventBus | None = None,
        routing: dict | None = None,
    ):
        self.endpoint = endpoint.rstrip("/")
        self.api_key = api_key
        self.auth_method = auth_method
        self.extra_headers = extra_headers or {}
        self.timeout = timeout
        self.events = event_bus
        self.routing = routing
        # Aggregate token usage across all successful responses. The runner
        # reads this to compute a realistic cost estimate.
        self.cumulative_tokens: dict[str, int] = {
            "prompt": 0, "completion": 0,
        }
        self._client: httpx.AsyncClient | None = None
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._min_interval = min_interval
        self._last_request_time = 0.0
        self._lock = asyncio.Lock()
        self._run_id = str(uuid.uuid4())[:8]

    def _emit(self, evt_type: EventType, data: dict) -> None:
        if self.events is not None:
            self.events.emit(Event(evt_type, data))

    def _record_usage(self, body: dict | None) -> None:
        if not body:
            return
        usage = body.get("usage")
        if not isinstance(usage, dict):
            return
        # Prefer OpenAI keys (prompt_tokens / completion_tokens).  Fall back
        # to Anthropic keys (input_tokens / output_tokens) ONLY when the
        # OpenAI key is absent — not when it is present but zero.
        prompt_raw = usage.get("prompt_tokens")
        if prompt_raw is None:
            prompt_raw = usage.get("input_tokens", 0)
        completion_raw = usage.get("completion_tokens")
        if completion_raw is None:
            completion_raw = usage.get("output_tokens", 0)
        self.cumulative_tokens["prompt"] += _safe_token_count(prompt_raw)
        self.cumulative_tokens["completion"] += _safe_token_count(completion_raw)

    async def __aenter__(self):
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout, connect=_CONNECT_TIMEOUT),
            follow_redirects=True,
        )
        return self

    async def __aexit__(self, *args):
        if self._client:
            await self._client.aclose()

    # ---------- header / url / params ----------

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

    async def _throttle(self) -> None:
        async with self._lock:
            now = time.perf_counter()
            wait = self._min_interval - (now - self._last_request_time)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request_time = time.perf_counter()

    def _require_entered(self) -> None:
        if self._client is None:
            raise RuntimeError(
                "RouterClient must be used as an async context manager "
                "(`async with RouterClient(...) as c:`). "
                "send()/get()/send_stream() are unavailable before __aenter__."
            )

    # ---------- public API ----------

    def _inject_routing(self, payload: dict) -> dict:
        """Inject routing config into the request payload if configured."""
        if not self.routing:
            return payload
        # Don't overwrite if probe already has routing
        if "routing" in payload:
            return payload
        return {**payload, "routing": self.routing}

    async def send(self, probe: ProbeRequest) -> ProbeResponse:
        self._require_entered()
        probe_id = str(uuid.uuid4())[:8]
        self._emit(EventType.PROBE_SENT, {
            "probe_id": probe_id,
            "endpoint_path": probe.endpoint_path,
            "description": probe.description,
        })
        for attempt in range(_MAX_RETRIES + 1):
            # Capture retry-after outside the semaphore so the sleep itself
            # does not hold a concurrency slot (otherwise a burst of 429s
            # freezes the whole client until every retry wakes up).
            retry_after: float | None = None
            async with self._semaphore:
                await self._throttle()
                t0 = time.perf_counter()
                try:
                    resp = await self._client.post(
                        self._url(probe.endpoint_path),
                        json=self._inject_routing(probe.payload),
                        headers=self._headers(probe_id),
                        params=self._query_params(),
                    )
                    elapsed = (time.perf_counter() - t0) * 1000
                    # Retry on 429 (standard rate-limit) and 401
                    # (some providers like OpenRouter return 401 under
                    # load instead of 429).
                    if resp.status_code in (429, 401) and attempt < _MAX_RETRIES:
                        retry_after = float(
                            resp.headers.get("retry-after", 2 * (attempt + 1))
                        )
                        logger.warning(
                            "%d received, retry %d after %.1fs",
                            resp.status_code, attempt + 1, retry_after,
                        )
                    else:
                        body = _safe_json(resp)
                        self._record_usage(body)
                        out = ProbeResponse(
                            status_code=resp.status_code,
                            body=body,
                            headers=dict(resp.headers),
                            raw_text=resp.text,
                            latency_ms=elapsed,
                        )
                        self._emit(EventType.PROBE_RECEIVED, {
                            "probe_id": probe_id,
                            "status_code": out.status_code,
                            "latency_ms": out.latency_ms,
                        })
                        return out
                except httpx.TimeoutException:
                    if attempt < _MAX_RETRIES:
                        retry_after = _timeout_backoff(attempt)
                        logger.warning(
                            "Timeout, retry %d after %.1fs",
                            attempt + 1, retry_after,
                        )
                    else:
                        err = _err_response("TIMEOUT", t0)
                        self._emit(EventType.PROBE_RECEIVED, {
                            "probe_id": probe_id, "error": "TIMEOUT",
                        })
                        return err
                except httpx.ConnectError as e:
                    err = _err_response(f"CONNECT: {_sanitize(str(e))}", t0)
                    self._emit(EventType.PROBE_RECEIVED, {
                        "probe_id": probe_id, "error": err.error,
                    })
                    return err
                except httpx.HTTPError as e:
                    err = _err_response(f"HTTP: {_sanitize(str(e))}", t0)
                    self._emit(EventType.PROBE_RECEIVED, {
                        "probe_id": probe_id, "error": err.error,
                    })
                    return err

            # Semaphore released. Backoff without blocking other requests.
            if retry_after is not None:
                await asyncio.sleep(retry_after)
        return ProbeResponse(status_code=0, error="MAX_RETRIES")

    async def get(
        self,
        path: str,
        params: dict[str, str] | None = None,
    ) -> ProbeResponse:
        self._require_entered()
        probe_id = str(uuid.uuid4())[:8]
        self._emit(EventType.PROBE_SENT, {
            "probe_id": probe_id, "endpoint_path": path, "method": "GET",
        })
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
                body = _safe_json(resp)
                self._record_usage(body)
                out = ProbeResponse(
                    status_code=resp.status_code,
                    body=body,
                    headers=dict(resp.headers),
                    raw_text=resp.text,
                    latency_ms=elapsed,
                )
                self._emit(EventType.PROBE_RECEIVED, {
                    "probe_id": probe_id,
                    "status_code": out.status_code,
                    "latency_ms": out.latency_ms,
                })
                return out
            except httpx.TimeoutException:
                err = _err_response("GET_TIMEOUT", t0)
                self._emit(EventType.PROBE_RECEIVED, {
                    "probe_id": probe_id, "error": "GET_TIMEOUT",
                })
                return err
            except httpx.HTTPError as e:
                err = _err_response(f"GET: {_sanitize(str(e))}", t0)
                self._emit(EventType.PROBE_RECEIVED, {
                    "probe_id": probe_id, "error": err.error,
                })
                return err

    async def send_stream(self, probe: ProbeRequest) -> ProbeResponse:
        """Streaming POST with the same retry semantics as ``send()``.

        Retries on 429 (honours ``Retry-After``) and on timeout (exponential
        backoff). The semaphore is released during backoff so a single
        rate-limited stream cannot starve concurrent probes.
        """
        self._require_entered()
        probe_id = str(uuid.uuid4())[:8]
        self._emit(EventType.PROBE_SENT, {
            "probe_id": probe_id,
            "endpoint_path": probe.endpoint_path,
            "description": probe.description,
            "stream": True,
        })
        resp = await self._stream_with_retry(probe, probe_id)
        self._record_usage(resp.body)
        self._emit(EventType.PROBE_RECEIVED, {
            "probe_id": probe_id,
            "status_code": resp.status_code,
            "latency_ms": resp.latency_ms,
            "error": resp.error,
        })
        return resp

    async def _stream_with_retry(
        self, probe: ProbeRequest, probe_id: str,
    ) -> ProbeResponse:
        last_t0 = 0.0
        for attempt in range(_MAX_RETRIES + 1):
            retry_after: float | None = None
            async with self._semaphore:
                await self._throttle()
                t0 = time.perf_counter()
                last_t0 = t0
                try:
                    resp, server_retry = await self._open_stream(
                        probe, probe_id, t0,
                    )
                    if resp is not None:
                        return resp  # success or non-429 error -> done
                    retry_after = server_retry or 2.0 * (attempt + 1)
                    logger.warning(
                        "stream 429, retry %d after %.1fs",
                        attempt + 1, retry_after,
                    )
                except httpx.TimeoutException:
                    if attempt < _MAX_RETRIES:
                        retry_after = _timeout_backoff(attempt)
                        logger.warning(
                            "stream timeout, retry %d after %.1fs",
                            attempt + 1, retry_after,
                        )
                    else:
                        return _err_response("STREAM_TIMEOUT", t0)
                except httpx.HTTPError as e:
                    return _err_response(
                        f"STREAM: {_sanitize(str(e))}", t0,
                    )

            if retry_after is not None:
                await asyncio.sleep(retry_after)
        return _err_response("STREAM_MAX_RETRIES", last_t0)

    async def _open_stream(
        self, probe: ProbeRequest, probe_id: str, t0: float,
    ) -> tuple[ProbeResponse | None, float | None]:
        """Open the SSE stream and assemble a ProbeResponse.

        Timeout semantics for streaming differ from non-streaming:
        httpx's ``read`` timeout applies to each individual socket read,
        which for SSE effectively means **inter-chunk timeout** — the stream
        can run for any total duration as long as chunks keep arriving
        within ``self.timeout`` seconds of each other.  This is the correct
        behavior: a 60-second stream generating tokens every 50ms will
        never hit the 60s read timeout.

        Returns ``(None, retry_after_seconds)`` when the upstream returned 429
        (signalling the caller should retry with the server-requested backoff).
        Returns ``(ProbeResponse, None)`` for any terminal outcome.
        """
        chunks: list[dict] = []
        timestamps: list[float] = []
        content = ""
        usage_block: dict | None = None
        finish_reason: str | None = None
        payload = self._inject_routing({**probe.payload, "stream": True})
        async with aconnect_sse(
            self._client,
            "POST",
            self._url(probe.endpoint_path),
            json=payload,
            headers=self._headers(probe_id),
            params=self._query_params(),
        ) as es:
            status_code = es.response.status_code
            headers = dict(es.response.headers)
            if status_code in (429, 401):
                try:
                    ra = float(headers.get("retry-after", "0"))
                except (TypeError, ValueError):
                    ra = None
                return None, ra or None
            async for event in es.aiter_sse():
                if event.data == "[DONE]":
                    break
                timestamps.append(time.perf_counter() - t0)
                try:
                    chunk = json.loads(event.data)
                    chunks.append(chunk)
                    choices = chunk.get("choices", [])
                    if choices:
                        delta = choices[0].get("delta", {})
                        c = delta.get("content", "")
                        if c:
                            content += c
                        fr = choices[0].get("finish_reason")
                        if fr:
                            finish_reason = fr
                    if "usage" in chunk:
                        usage_block = chunk["usage"]
                except (json.JSONDecodeError, ValueError):
                    chunks.append({"_raw": event.data})
        return ProbeResponse(
            status_code=status_code,
            body={
                "full_content": content,
                "chunk_count": len(chunks),
                "finish_reason": finish_reason,
                "usage": usage_block,
            },
            headers=headers,
            raw_text=content,
            latency_ms=(time.perf_counter() - t0) * 1000,
            chunks=chunks,
            chunk_timestamps=timestamps,
        ), None

    async def send_concurrent(
        self, probes: list[ProbeRequest]
    ) -> list[ProbeResponse]:
        return list(await asyncio.gather(*[self.send(p) for p in probes]))


def _safe_json(resp: httpx.Response) -> dict | None:
    try:
        return resp.json()
    except (json.JSONDecodeError, ValueError):
        return None


def _safe_token_count(raw: object) -> int:
    """Coerce a possibly-malformed token count into a non-negative int."""
    try:
        return max(0, int(raw))
    except (TypeError, ValueError):
        return 0


def _err_response(error: str, t0: float) -> ProbeResponse:
    return ProbeResponse(
        status_code=0,
        error=error,
        latency_ms=(time.perf_counter() - t0) * 1000,
    )
