#!/usr/bin/env python3
"""Launch the Router Auditor API server.

Prefers granian (Rust-backed ASGI), falls back to uvicorn.
Requires ``AUDITOR_API_KEY`` env var for API auth.
"""
from __future__ import annotations

import argparse
import logging
import os
import sys


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Router Auditor API Server")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8900)
    p.add_argument("--workers", type=int, default=1)
    p.add_argument("--log-level", default="info",
                   choices=["debug", "info", "warning", "error"])
    return p


def main() -> int:
    args = build_parser().parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )
    log = logging.getLogger("router-auditor.serve")

    if not os.environ.get("AUDITOR_API_KEY"):
        log.error("AUDITOR_API_KEY environment variable is required")
        return 2

    try:
        from granian import Granian
        from granian.constants import Interfaces
        log.info("Starting with granian on %s:%d", args.host, args.port)
        Granian(
            target="src.api.app:app",
            address=args.host,
            port=args.port,
            workers=args.workers,
            interface=Interfaces.ASGI,
            log_level=args.log_level,
            http="auto",
            websockets=True,
            backpressure=128,
        ).serve()
        return 0
    except ImportError:
        log.info("granian unavailable, trying uvicorn...")

    try:
        import uvicorn
        log.info("Starting with uvicorn on %s:%d", args.host, args.port)
        uvicorn.run(
            "src.api.app:app",
            host=args.host,
            port=args.port,
            workers=args.workers,
            log_level=args.log_level,
        )
        return 0
    except ImportError:
        log.error("No ASGI server installed. Run: pip install granian OR uvicorn")
        return 1


if __name__ == "__main__":
    sys.exit(main())
