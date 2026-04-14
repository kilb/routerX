"""Nonce / canary generators used by detectors for unique session markers."""
from __future__ import annotations

import random
import string
import time

_ALPHANUM = string.ascii_uppercase + string.digits


def generate_nonce(prefix: str = "NONCE", length: int = 8) -> str:
    return f"{prefix}-{''.join(random.choices(_ALPHANUM, k=length))}"


def generate_timestamp_nonce() -> str:
    return f"TS-{int(time.time())}-{random.randint(1000, 9999)}"


def generate_canary(prefix: str = "CANARY") -> str:
    return generate_nonce(prefix, 12)
