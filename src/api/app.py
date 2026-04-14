"""FastAPI application factory."""
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
    try:
        yield
    finally:
        logger.info("Router Auditor API shutting down — cancelling pending tasks")
        await tm.shutdown()


def create_app() -> FastAPI:
    app = FastAPI(
        title="Router Auditor API",
        description="LLM Router admission test API",
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
