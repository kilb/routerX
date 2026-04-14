"""Auto-discover detector modules so their ``@detector`` decorators fire.

Every file in this package whose name starts with ``d`` is imported at
package-import time, populating ``registry._REGISTRY``. Entry points should
import this package early (e.g. ``import src.detectors  # noqa: F401``).
"""
from __future__ import annotations

import importlib
import pathlib
import pkgutil

_pkg = pathlib.Path(__file__).parent
for m in pkgutil.iter_modules([str(_pkg)]):
    if m.name.startswith("d"):
        importlib.import_module(f".{m.name}", __package__)
