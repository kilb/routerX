"""Pydantic models for the Router Auditor API layer."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class CreateTestRequest(BaseModel):
    router_endpoint: str = Field(..., description="Base URL of the router under test")
    api_key: str = Field(..., description="API key for the router")
    claimed_model: str = Field(default="gpt-4o")
    claimed_provider: str = Field(
        default="any", pattern="^(openai|anthropic|gemini|any)$",
    )
    claimed_single_route: bool = False
    capabilities: list[str] = Field(default=["text"])
    auth_method: str = Field(
        default="bearer", pattern="^(bearer|x-api-key|query)$",
    )
    api_format: str = Field(
        default="openai", pattern="^(openai|anthropic|auto)$",
    )
    extra_headers: dict[str, str] = Field(default_factory=dict)
    direct_endpoint: str | None = None
    direct_api_key: str | None = None
    direct_auth_method: str | None = Field(
        default=None, pattern="^(bearer|x-api-key|query)$",
    )
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


class CreateBenchmarkRequest(BaseModel):
    router_endpoint: str = Field(..., description="Base URL of the router under test")
    api_key: str = Field(..., description="API key for the router")
    claimed_model: str = Field(default="gpt-4o")
    auth_method: str = Field(
        default="bearer", pattern="^(bearer|x-api-key|query)$",
    )
    timeout: float = Field(default=30.0, ge=5.0, le=120.0)


class CreateBenchmarkResponse(BaseModel):
    task_id: str
    status: TaskStatus
    message: str
    ws_url: str


class BenchmarkInfo(BaseModel):
    bench_id: str
    bench_name: str
    category: str
    description: str


class BenchmarkTaskSummary(BaseModel):
    task_id: str
    task_type: str
    status: TaskStatus
    created_at: datetime
    completed_at: datetime | None = None
    router_endpoint: str
    claimed_model: str
    overall_grade: str | None = None
    progress: str | None = None


class BenchmarkTaskDetail(BenchmarkTaskSummary):
    benchmark_report: dict[str, Any] | None = None
    error: str | None = None
