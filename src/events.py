"""Minimal synchronous event bus for observer-style hooks.

Not a public API. Consumers subscribe via ``bus.on(EventType.X, handler)``
and emit via ``bus.emit(Event(...))``. Handler errors are swallowed and
logged so a bad listener cannot abort a test run.
"""
from __future__ import annotations

import logging
from enum import Enum
from typing import Any, Callable

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

    def on(self, event_type: EventType, handler: Callable) -> "EventBus":
        self._handlers.setdefault(event_type, []).append(handler)
        return self

    def emit(self, event: Event) -> None:
        for handler in self._handlers.get(event.type, []):
            try:
                handler(event)
            except Exception as e:
                logger.error("Event handler error: %s", e)

    def off(self, event_type: EventType, handler: Callable) -> None:
        handlers = self._handlers.get(event_type, [])
        if handler in handlers:
            handlers.remove(handler)
