"""Global pytest fixtures for Router Auditor tests.

Note: we do NOT override the ``event_loop`` fixture — pytest-asyncio >= 0.23
deprecated this pattern. The ``asyncio_mode = "auto"`` setting in
``pyproject.toml`` handles loop management.
"""
from __future__ import annotations

import pytest


@pytest.fixture
def test_config():
    from src.models import TestConfig
    return TestConfig(
        router_endpoint="http://localhost:8999/v1",
        api_key="test-key",
    )


@pytest.fixture
def mock_config_factory():
    """Build a TestConfig pointing at the mock server on a given port."""
    from src.models import TestConfig

    def _factory(port: int, **overrides):
        kwargs = dict(
            router_endpoint=f"http://127.0.0.1:{port}/v1",
            api_key="test-key",
            timeout=10.0,
            min_request_interval=0.0,
        )
        kwargs.update(overrides)
        return TestConfig(**kwargs)

    return _factory
