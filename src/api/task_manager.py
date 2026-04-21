"""Async task manager for API test runs.

Each TaskInfo owns its own EventBus; events are broadcast to WebSocket
subscribers via per-connection asyncio.Queue. TaskManager throttles
concurrent runs via a semaphore.

Completed tasks are persisted as JSON files under ``data/tasks/`` so
they survive server restarts.  On startup, ``TaskManager._load_persisted``
reads them back into the in-memory store.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import pathlib
import traceback
import uuid
from datetime import datetime, timezone

import httpx

import src.detectors  # noqa: F401  — trigger auto-scan

from src.benchmarks.runner import BenchmarkReport, BenchmarkRunner
from src.events import Event, EventBus, EventType
from src.models import AuthMethod, ProviderType, TestConfig, TestReport
from src.runner import TestRunner

from .schemas import TaskStatus

logger = logging.getLogger("router-auditor.api.tasks")


class TaskInfo:
    def __init__(
        self,
        task_id: str,
        config: TestConfig,
        only: list[str] | None = None,
        callback_url: str | None = None,
        task_type: str = "audit",
    ):
        self.task_id = task_id
        self.config = config
        self.only = only
        self.callback_url = callback_url
        self.task_type = task_type
        self.status: TaskStatus = TaskStatus.PENDING
        self.created_at = datetime.now(timezone.utc)
        self.completed_at: datetime | None = None
        self.report: TestReport | None = None
        self.benchmark_report: dict | None = None
        self.error: str | None = None
        # Remains None until the runner enumerates applicable detectors —
        # consumers seeing ``None`` know "not started yet"; a value means
        # "N of TOTAL complete".
        self.progress: str | None = None
        self.event_bus = EventBus()
        self._task: asyncio.Task | None = None
        # Snapshot-safe iteration — see _broadcast. Mutations in the WS
        # handler append/remove under try/finally; _broadcast snapshots
        # before iterating so concurrent mutation cannot crash us.
        self.ws_subscribers: list[asyncio.Queue] = []

        self.event_bus.on(EventType.DETECTOR_END, self._on_event)
        self.event_bus.on(EventType.STAGE_START, self._on_event)
        self.event_bus.on(EventType.ABORT, self._on_event)

    def _on_event(self, event: Event) -> None:
        self._broadcast({
            "type": event.type.value,
            "data": event.data,
            "progress": self.progress,
        })

    def _broadcast(self, message: dict) -> None:
        # Snapshot the list before iterating so a concurrent append/remove
        # in the WS handler cannot cause ``RuntimeError: list changed size
        # during iteration``.
        for q in list(self.ws_subscribers):
            try:
                q.put_nowait(message)
            except asyncio.QueueFull:
                pass


_DATA_DIR = pathlib.Path(__file__).resolve().parent.parent.parent / "data" / "tasks"


class TaskManager:
    def __init__(self, max_concurrent: int = 3):
        self._tasks: dict[str, TaskInfo] = {}
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._load_persisted()

    # ---------- persistence ----------

    def _load_persisted(self) -> None:
        """Load completed tasks from disk on startup."""
        if not _DATA_DIR.exists():
            return
        loaded = 0
        for path in sorted(_DATA_DIR.glob("*.json")):
            try:
                raw = json.loads(path.read_text())
                task_id = raw["task_id"]
                # Reconstruct a minimal TestConfig (API key redacted on disk)
                config = TestConfig(
                    router_endpoint=raw.get("router_endpoint", ""),
                    api_key="***",
                    claimed_model=raw.get("claimed_model", ""),
                    claimed_provider=ProviderType(raw.get("claimed_provider", "any")),
                )
                info = TaskInfo(task_id, config, task_type=raw.get("task_type", "audit"))
                info.status = TaskStatus(raw.get("status", "completed"))
                info.created_at = datetime.fromisoformat(raw["created_at"])
                if raw.get("completed_at"):
                    info.completed_at = datetime.fromisoformat(raw["completed_at"])
                if raw.get("report") and raw["report"].get("results"):
                    info.report = TestReport(**raw["report"])
                if raw.get("benchmark_report"):
                    info.benchmark_report = raw["benchmark_report"]
                info.progress = raw.get("progress")
                self._tasks[task_id] = info
                loaded += 1
            except Exception as e:
                logger.warning("Failed to load %s: %s", path.name, e)
        if loaded:
            logger.info("Loaded %d persisted tasks from %s", loaded, _DATA_DIR)

    def _persist(self, info: TaskInfo) -> None:
        """Save a completed task to disk."""
        try:
            _DATA_DIR.mkdir(parents=True, exist_ok=True)
            data = {
                "task_id": info.task_id,
                "task_type": info.task_type,
                "status": info.status.value,
                "created_at": info.created_at.isoformat(),
                "completed_at": info.completed_at.isoformat() if info.completed_at else None,
                "router_endpoint": info.config.router_endpoint,
                "claimed_model": info.config.claimed_model,
                "claimed_provider": info.config.claimed_provider.value,
                "progress": info.progress,
            }
            if info.report:
                data["report"] = info.report.model_dump()
            if info.benchmark_report:
                data["benchmark_report"] = info.benchmark_report
            path = _DATA_DIR / f"{info.task_id}.json"
            path.write_text(json.dumps(data, indent=2, default=str))
        except Exception as e:
            logger.warning("Failed to persist %s: %s", info.task_id, e)

    def _delete_persisted(self, task_id: str) -> None:
        """Remove persisted file for a deleted task."""
        path = _DATA_DIR / f"{task_id}.json"
        try:
            path.unlink(missing_ok=True)
        except Exception:
            pass

    def create_task(
        self,
        config: TestConfig,
        only: list[str] | None = None,
        callback_url: str | None = None,
    ) -> TaskInfo:
        task_id = str(uuid.uuid4())[:12]
        info = TaskInfo(task_id, config, only, callback_url)
        self._tasks[task_id] = info
        info._task = asyncio.create_task(self._run(info))
        return info

    def create_benchmark_task(
        self,
        router_endpoint: str,
        api_key: str,
        claimed_model: str = "gpt-4o",
        auth_method: str = "bearer",
        timeout: float = 30.0,
    ) -> TaskInfo:
        config = TestConfig(
            router_endpoint=router_endpoint,
            api_key=api_key,
            claimed_model=claimed_model,
            auth_method=AuthMethod(auth_method),
            timeout=timeout,
        )
        task_id = str(uuid.uuid4())[:12]
        info = TaskInfo(task_id, config, task_type="benchmark")
        self._tasks[task_id] = info
        info._task = asyncio.create_task(self._run_benchmark(info))
        return info

    async def _run_benchmark(self, info: TaskInfo) -> None:
        async with self._semaphore:
            info.status = TaskStatus.RUNNING
            try:
                runner = BenchmarkRunner(info.config)

                def on_progress(completed: int, total: int, bench_id: str) -> None:
                    info.progress = f"{completed}/{total}"

                def on_result(result) -> None:
                    info._broadcast({
                        "type": "benchmark_end",
                        "data": result.to_dict(),
                        "progress": info.progress,
                    })

                report: BenchmarkReport = await runner.run_all(
                    on_progress=on_progress, on_result=on_result,
                )
                info.benchmark_report = report.to_dict()
                info.status = TaskStatus.COMPLETED
                info.completed_at = datetime.now(timezone.utc)
                self._persist(info)

            except asyncio.CancelledError:
                info.status = TaskStatus.CANCELLED
            except Exception:
                info.status = TaskStatus.FAILED
                info.error = traceback.format_exc()
            finally:
                info._broadcast({
                    "type": "task_end",
                    "data": {
                        "status": info.status.value,
                        "overall_grade": (
                            info.benchmark_report.get("overall_grade")
                            if info.benchmark_report else None
                        ),
                    },
                })

    async def _run(self, info: TaskInfo) -> None:
        async with self._semaphore:
            info.status = TaskStatus.RUNNING
            try:
                runner = TestRunner(
                    info.config, only=info.only, event_bus=info.event_bus,
                )
                total = len(runner._get_applicable_detectors())

                def on_progress(completed: int, _total: int, *_args) -> None:
                    info.progress = f"{completed}/{total}"

                runner.on_progress = on_progress
                report = await runner.run_all()
                info.report = report
                info.status = TaskStatus.COMPLETED
                info.completed_at = datetime.now(timezone.utc)
                self._persist(info)

                if info.callback_url:
                    await self._callback(info)

            except asyncio.CancelledError:
                info.status = TaskStatus.CANCELLED
            except Exception:
                info.status = TaskStatus.FAILED
                info.error = traceback.format_exc()
            finally:
                info._broadcast({
                    "type": "task_end",
                    "data": {
                        "status": info.status.value,
                        "tier": (
                            info.report.tier_assignment if info.report else None
                        ),
                    },
                })

    async def _callback(self, info: TaskInfo) -> None:
        if not info.callback_url or not info.report:
            return
        try:
            async with httpx.AsyncClient(timeout=10.0) as c:
                await c.post(info.callback_url, json={
                    "task_id": info.task_id,
                    "status": info.status.value,
                    "report": info.report.model_dump(),
                })
        except Exception as e:
            logger.warning("Callback failed: %s", e)

    def get_task(self, task_id: str) -> TaskInfo | None:
        return self._tasks.get(task_id)

    def list_tasks(
        self,
        limit: int = 20,
        offset: int = 0,
        status: TaskStatus | None = None,
        endpoint_filter: str | None = None,
    ) -> list[TaskInfo]:
        tasks = sorted(
            self._tasks.values(), key=lambda t: t.created_at, reverse=True,
        )
        if status:
            tasks = [t for t in tasks if t.status == status]
        if endpoint_filter:
            tasks = [
                t for t in tasks if endpoint_filter in t.config.router_endpoint
            ]
        return tasks[offset:offset + limit]

    def cancel_task(self, task_id: str) -> bool:
        info = self._tasks.get(task_id)
        if not info or info.status != TaskStatus.RUNNING:
            return False
        if info._task:
            info._task.cancel()
        return True

    def delete_task(self, task_id: str) -> bool:
        info = self._tasks.get(task_id)
        if not info:
            return False
        if info.status == TaskStatus.RUNNING:
            return False
        # Wake any open WS subscribers so they can cleanly close, instead of
        # waiting 30s for the next ping when their TaskInfo vanishes.
        info._broadcast({"type": "task_deleted", "data": {"task_id": task_id}})
        del self._tasks[task_id]
        self._delete_persisted(task_id)
        return True

    def task_exists(self, task_id: str) -> bool:
        """Distinguish 404 (not found) from 409 (running) for REST correctness."""
        return task_id in self._tasks

    async def shutdown(self) -> None:
        """Cancel all pending/running tasks on lifespan shutdown.

        Without this, FastAPI TestClient exit leaves orphan asyncio.Tasks
        running after the event loop closes — causing ``Task was destroyed
        but it is pending!`` warnings and in CI intermittent failures.
        """
        pending = [
            info._task for info in self._tasks.values()
            if info._task is not None and not info._task.done()
        ]
        for t in pending:
            t.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

    @property
    def active_count(self) -> int:
        return sum(
            1 for t in self._tasks.values() if t.status == TaskStatus.RUNNING
        )

    @property
    def total_completed(self) -> int:
        return sum(
            1 for t in self._tasks.values() if t.status == TaskStatus.COMPLETED
        )
