"""Async task manager for API test runs.

Each TaskInfo owns its own EventBus; events are broadcast to WebSocket
subscribers via per-connection asyncio.Queue. TaskManager throttles
concurrent runs via a semaphore.
"""
from __future__ import annotations

import asyncio
import logging
import traceback
import uuid
from datetime import datetime, timezone

import httpx

import src.detectors  # noqa: F401  — trigger auto-scan

from src.events import Event, EventBus, EventType
from src.models import TestConfig, TestReport
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
    ):
        self.task_id = task_id
        self.config = config
        self.only = only
        self.callback_url = callback_url
        self.status: TaskStatus = TaskStatus.PENDING
        self.created_at = datetime.now(timezone.utc)
        self.completed_at: datetime | None = None
        self.report: TestReport | None = None
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


class TaskManager:
    def __init__(self, max_concurrent: int = 3):
        self._tasks: dict[str, TaskInfo] = {}
        self._semaphore = asyncio.Semaphore(max_concurrent)

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
