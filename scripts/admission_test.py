#!/usr/bin/env python3
"""CLI entry: run the admission test suite against a Router endpoint.

Exit code 1 if the Router is BLACKLISTED, 0 otherwise.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys

import src.detectors  # noqa: F401

from src.registry import get_all_detectors
from src.models import (
    ApiFormat,
    AuthMethod,
    Capability,
    ProviderType,
    ScanMode,
    TestConfig,
)
from src.reporter import print_cli_report, write_junit_xml
from src.runner import TestRunner


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Router Admission Test")
    p.add_argument("--endpoint", required=True)
    p.add_argument("--api-key", required=True)
    p.add_argument("--model", default="gpt-4o")
    p.add_argument("--provider", default="any",
                   choices=["openai", "anthropic", "gemini", "any"])
    p.add_argument("--single-route", action="store_true")
    p.add_argument("--capabilities", nargs="+", default=["text"],
                   choices=["text", "vision", "pdf", "audio",
                            "task_model", "tool_calling"])
    p.add_argument("--auth-method", default="bearer",
                   choices=["bearer", "x-api-key", "query"])
    p.add_argument("--api-format", default="openai",
                   choices=["openai", "anthropic", "auto"])
    p.add_argument("--direct-endpoint")
    p.add_argument("--direct-api-key")
    p.add_argument("--direct-auth-method",
                   choices=["bearer", "x-api-key", "query"])
    p.add_argument("--output", default="report.json")
    p.add_argument("--junit-xml")
    p.add_argument("--timeout", type=float, default=30.0)
    p.add_argument("--log-level", default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    p.add_argument("--scan-mode", default="full",
                   choices=["full", "essential"],
                   help="full: all 85 detectors; essential: ~45 high-confidence only")
    p.add_argument("--only", nargs="+",
                   help="Run only these detector IDs (e.g. D25 D28)")
    return p


def main() -> int:
    args = build_parser().parse_args()

    # Validate --only IDs up-front so users get immediate feedback instead
    # of an empty report.
    if args.only:
        known = set(get_all_detectors())
        unknown = [d for d in args.only if d not in known]
        if unknown:
            print(
                f"ERROR: unknown detector IDs in --only: {unknown}\n"
                f"Known: {sorted(known)}",
                file=sys.stderr,
            )
            return 2

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
        direct_auth_method=(
            AuthMethod(args.direct_auth_method)
            if args.direct_auth_method else None
        ),
        scan_mode=ScanMode(args.scan_mode),
        timeout=args.timeout,
    )

    runner = TestRunner(config, only=args.only)
    report = asyncio.run(runner.run_all())
    print_cli_report(report)

    with open(args.output, "w") as f:
        f.write(report.model_dump_json(indent=2))

    if args.junit_xml:
        write_junit_xml(report, args.junit_xml)

    return 1 if report.tier_assignment == "BLACKLIST" else 0


if __name__ == "__main__":
    sys.exit(main())
