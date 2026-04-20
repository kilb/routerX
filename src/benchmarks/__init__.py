"""Auto-discover benchmark modules so their ``@benchmark`` decorators fire.

Every file in this package whose name starts with ``p`` or ``r`` is imported
at package-import time, populating ``base._BENCH_REGISTRY``.  Entry points
should import this package early (e.g. ``import src.benchmarks  # noqa: F401``).
"""
from __future__ import annotations

import importlib
import pathlib
import pkgutil

_pkg = pathlib.Path(__file__).parent
for _m in pkgutil.iter_modules([str(_pkg)]):
    if _m.name.startswith(("p", "r")) and _m.name != "runner":
        importlib.import_module(f".{_m.name}", __package__)
