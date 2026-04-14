#!/usr/bin/env python3
"""Run self_test() on every registered detector sequentially."""
from __future__ import annotations

import contextlib
import io
import sys

import src.detectors  # noqa: F401 — trigger auto-scan

from src.registry import get_all_detectors


def main() -> int:
    total = 0
    failed: list[str] = []
    for cls in sorted(get_all_detectors().values(), key=lambda c: c.detector_id):
        total += 1
        print(f"\n--- {cls.detector_id} ({cls.detector_name}) ---")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cls.self_test()
        output = buf.getvalue()
        print(output, end="")
        last = output.strip().splitlines()[-1] if output.strip() else ""
        if last.startswith("[FAIL]"):
            failed.append(cls.detector_id)
    print("\n" + "=" * 60)
    print(f"  {total - len(failed)}/{total} detectors pass self-test")
    if failed:
        print(f"  FAILED: {failed}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
