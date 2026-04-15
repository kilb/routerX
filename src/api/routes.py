"""FastAPI routes for the Router Auditor API."""
from __future__ import annotations

import asyncio
import logging

from pydantic import BaseModel

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import Response

import src.detectors  # noqa: F401

from src.models import (
    ApiFormat,
    AuthMethod,
    Capability,
    ProviderType,
    TaskModelConfig,
    TestConfig,
)
from src.registry import get_all_detectors
from src.reporter import write_junit_xml

from .auth import verify_token
from .schemas import (
    CreateTestRequest,
    CreateTestResponse,
    DetectorInfo,
    HealthResponse,
    TaskDetail,
    TaskStatus,
    TaskSummary,
)
from .task_manager import TaskManager, TaskInfo

logger = logging.getLogger("router-auditor.api")
router = APIRouter(prefix="/api/v1")

_task_manager: TaskManager | None = None


def get_tm() -> TaskManager:
    assert _task_manager is not None, "TaskManager not initialized"
    return _task_manager


def set_task_manager(tm: TaskManager) -> None:
    global _task_manager
    _task_manager = tm


def _summary(info: TaskInfo) -> TaskSummary:
    return TaskSummary(
        task_id=info.task_id,
        status=info.status,
        created_at=info.created_at,
        completed_at=info.completed_at,
        router_endpoint=info.config.router_endpoint,
        claimed_model=info.config.claimed_model,
        tier_assignment=info.report.tier_assignment if info.report else None,
        overall_verdict=(
            info.report.overall_verdict.value if info.report else None
        ),
        progress=info.progress,
    )


_SENSITIVE_HEADER_KEYS = {
    "authorization", "x-api-key", "api-key", "cookie", "set-cookie",
    "proxy-authorization", "x-auth-token",
}


def _scrub_headers(headers: dict[str, str]) -> dict[str, str]:
    """Mask sensitive values while preserving keys for observability."""
    return {
        k: ("***" if k.lower() in _SENSITIVE_HEADER_KEYS else v)
        for k, v in headers.items()
    }


def _detail(info: TaskInfo) -> TaskDetail:
    config_dump = info.config.model_dump(exclude={"api_key", "direct_api_key"})
    # extra_headers might carry Authorization, Cookie, etc. — scrub per-key
    # instead of dropping the whole field, so operators can still see which
    # headers were sent.
    if "extra_headers" in config_dump and config_dump["extra_headers"]:
        config_dump["extra_headers"] = _scrub_headers(config_dump["extra_headers"])
    return TaskDetail(
        task_id=info.task_id,
        status=info.status,
        created_at=info.created_at,
        completed_at=info.completed_at,
        router_endpoint=info.config.router_endpoint,
        claimed_model=info.config.claimed_model,
        tier_assignment=info.report.tier_assignment if info.report else None,
        overall_verdict=(
            info.report.overall_verdict.value if info.report else None
        ),
        progress=info.progress,
        config=config_dump,
        report=info.report.model_dump() if info.report else None,
        error=info.error,
    )


@router.post(
    "/tests",
    response_model=CreateTestResponse,
)
async def create_test(req: CreateTestRequest):
    # Validate --only IDs up-front so users get an actionable 400 instead of
    # a ghost task that completes with zero results.
    if req.only:
        known = set(get_all_detectors())
        unknown = [d for d in req.only if d not in known]
        if unknown:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Unknown detector IDs in 'only': {unknown}. "
                    f"Known detectors: {sorted(known)}"
                ),
            )
    task_cfg = (
        TaskModelConfig(**req.task_model_config) if req.task_model_config else None
    )
    config = TestConfig(
        router_endpoint=req.router_endpoint,
        api_key=req.api_key,
        claimed_model=req.claimed_model,
        claimed_provider=ProviderType(req.claimed_provider),
        claimed_single_route=req.claimed_single_route,
        capabilities=[Capability(c) for c in req.capabilities],
        auth_method=AuthMethod(req.auth_method),
        api_format=ApiFormat(req.api_format),
        extra_headers=req.extra_headers,
        direct_endpoint=req.direct_endpoint,
        direct_api_key=req.direct_api_key,
        direct_auth_method=(
            AuthMethod(req.direct_auth_method) if req.direct_auth_method else None
        ),
        task_model_config=task_cfg,
        timeout=req.timeout,
    )
    info = get_tm().create_task(config, only=req.only, callback_url=req.callback_url)
    return CreateTestResponse(
        task_id=info.task_id,
        status=info.status,
        message="Test created and queued",
        ws_url=f"/api/v1/tests/{info.task_id}/ws",
    )


@router.get(
    "/tests",
    response_model=list[TaskSummary],
    dependencies=[Depends(verify_token)],
)
async def list_tests(
    limit: int = 20,
    offset: int = 0,
    status: TaskStatus | None = None,
    endpoint: str | None = None,
):
    return [_summary(t) for t in get_tm().list_tasks(limit, offset, status, endpoint)]


@router.get(
    "/tests/{task_id}",
    response_model=TaskDetail,
    dependencies=[Depends(verify_token)],
)
async def get_test(task_id: str):
    info = get_tm().get_task(task_id)
    if not info:
        raise HTTPException(404, "Not found")
    return _detail(info)


@router.get("/tests/{task_id}/report", dependencies=[Depends(verify_token)])
async def get_report(task_id: str):
    info = get_tm().get_task(task_id)
    if not info:
        raise HTTPException(404, "Not found")
    if info.status != TaskStatus.COMPLETED or not info.report:
        raise HTTPException(400, f"Not completed: {info.status.value}")
    return Response(
        content=info.report.model_dump_json(indent=2),
        media_type="application/json",
        headers={
            "Content-Disposition": f"attachment; filename=report_{task_id}.json"
        },
    )


@router.get("/tests/{task_id}/junit", dependencies=[Depends(verify_token)])
async def get_junit(task_id: str):
    info = get_tm().get_task(task_id)
    if not info:
        raise HTTPException(404, "Not found")
    if info.status != TaskStatus.COMPLETED or not info.report:
        raise HTTPException(400, f"Not completed: {info.status.value}")
    # ``write_junit_xml`` currently only accepts a path, so write to a temp
    # file and unlink on exit. ``delete=False`` + manual unlink ensures the
    # file is readable on Windows (which forbids reading a still-open handle).
    import os
    import tempfile

    tmp = tempfile.NamedTemporaryFile(
        suffix=".xml", delete=False, mode="w", encoding="utf-8",
    )
    try:
        tmp.close()
        write_junit_xml(info.report, tmp.name)
        with open(tmp.name, "r", encoding="utf-8") as fh:
            content = fh.read()
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
    return Response(
        content=content,
        media_type="application/xml",
        headers={
            "Content-Disposition": f"attachment; filename=report_{task_id}.xml"
        },
    )


@router.post("/tests/{task_id}/cancel", dependencies=[Depends(verify_token)])
async def cancel_test(task_id: str):
    tm = get_tm()
    if not tm.task_exists(task_id):
        raise HTTPException(404, "Not found")
    if tm.cancel_task(task_id):
        return {"message": "Cancelled"}
    raise HTTPException(409, "Task is not running")


@router.delete("/tests/{task_id}", dependencies=[Depends(verify_token)])
async def delete_test(task_id: str):
    tm = get_tm()
    if not tm.task_exists(task_id):
        raise HTTPException(404, "Not found")
    if tm.delete_task(task_id):
        return {"message": "Deleted"}
    raise HTTPException(409, "Task is still running; cancel first")


@router.websocket("/tests/{task_id}/ws")
async def ws_progress(websocket: WebSocket, task_id: str):
    info = get_tm().get_task(task_id)
    if not info:
        await websocket.close(code=4004, reason="Not found")
        return

    await websocket.accept()
    queue: asyncio.Queue = asyncio.Queue(maxsize=100)
    info.ws_subscribers.append(queue)

    try:
        await websocket.send_json({
            "type": "status",
            "data": {
                "status": info.status.value, "progress": info.progress,
            },
        })

        if info.status in (
            TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED,
        ):
            await websocket.send_json({
                "type": "task_end",
                "data": {
                    "status": info.status.value,
                    "tier": (
                        info.report.tier_assignment if info.report else None
                    ),
                },
            })
            await websocket.close()
            return

        while True:
            try:
                msg = await asyncio.wait_for(queue.get(), timeout=30.0)
                await websocket.send_json(msg)
                if msg.get("type") == "task_end":
                    break
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping"})
    except WebSocketDisconnect:
        pass
    finally:
        if queue in info.ws_subscribers:
            info.ws_subscribers.remove(queue)
        try:
            await websocket.close()
        except Exception:
            pass


@router.get("/detectors", response_model=list[DetectorInfo])
async def list_detectors():
    return [
        DetectorInfo(
            detector_id=c.detector_id,
            detector_name=c.detector_name,
            priority=c.priority.value,
            judge_mode=c.judge_mode.value,
            request_count=c.request_count,
            required_capabilities=[cap.value for cap in c.required_capabilities],
            required_provider=c.required_provider.value,
            requires_direct=c.requires_direct,
            requires_single_route_claim=c.requires_single_route_claim,
            description=c.description,
        )
        for c in sorted(
            get_all_detectors().values(), key=lambda c: c.detector_id
        )
    ]


@router.get("/health", response_model=HealthResponse)
async def health():
    tm = get_tm()
    return HealthResponse(
        active_tasks=tm.active_count,
        total_completed=tm.total_completed,
    )


class ProbeModelsRequest(BaseModel):
    router_endpoint: str
    api_key: str
    auth_method: str = "bearer"


class ModelInfo(BaseModel):
    id: str
    owned_by: str | None = None


@router.post("/probe-models", response_model=list[ModelInfo])
async def probe_models(req: ProbeModelsRequest):
    """Fetch available models from a router's /v1/models endpoint."""
    import httpx

    endpoint = req.router_endpoint.rstrip("/")
    # Strip known API path suffixes (same logic as TestConfig validator).
    for suffix in ("/v1/chat/completions", "/chat/completions",
                   "/v1/messages", "/messages", "/v1"):
        if endpoint.endswith(suffix):
            endpoint = endpoint[:-len(suffix)]
            break

    headers: dict[str, str] = {"Accept": "application/json"}
    if req.auth_method == "bearer":
        headers["Authorization"] = f"Bearer {req.api_key}"
    elif req.auth_method == "x-api-key":
        headers["x-api-key"] = req.api_key

    params = {"api_key": req.api_key} if req.auth_method == "query" else None

    # Try /v1/models first (OpenAI standard), then /models as fallback.
    async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
        for path in ("/v1/models", "/models"):
            try:
                url = endpoint + path
                resp = await client.get(url, headers=headers, params=params)
                if resp.status_code != 200:
                    continue
                body = resp.json()
                data = body.get("data") or body.get("models") or []
                if not isinstance(data, list):
                    continue
                models = []
                for m in data:
                    if isinstance(m, dict) and m.get("id"):
                        models.append(ModelInfo(
                            id=m["id"],
                            owned_by=m.get("owned_by"),
                        ))
                    elif isinstance(m, str):
                        models.append(ModelInfo(id=m))
                if models:
                    # Sort: put common frontier models first.
                    models.sort(key=lambda x: (
                        0 if any(k in x.id.lower() for k in (
                            "gpt-4", "claude", "gemini", "o1", "o3",
                        )) else 1,
                        x.id,
                    ))
                    return models
            except Exception as exc:
                logger.debug("probe-models %s failed: %s", path, exc)
                continue
    raise HTTPException(
        status_code=502,
        detail="Could not fetch models from the router endpoint",
    )
