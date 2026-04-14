"""API integration tests using FastAPI TestClient."""
from __future__ import annotations

import os

import pytest


@pytest.fixture
def api_client():
    os.environ["AUDITOR_API_KEY"] = "test-secret"
    from fastapi.testclient import TestClient

    from src.api.app import create_app

    app = create_app()
    with TestClient(app) as client:
        yield client


def test_health_endpoint(api_client):
    r = api_client.get("/api/v1/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["active_tasks"] == 0


def test_list_detectors_returns_38(api_client):
    """36 previous + D24c (multi-turn history) + D29b (prompt cache) = 38."""
    r = api_client.get("/api/v1/detectors")
    assert r.status_code == 200
    detectors = r.json()
    assert len(detectors) == 38
    ids = {d["detector_id"] for d in detectors}
    for did in ("D25", "D28", "D45", "D45b", "D45c", "D24c", "D29b"):
        assert did in ids, f"missing {did}"


def test_auth_required_for_tests(api_client):
    r = api_client.get("/api/v1/tests")
    assert r.status_code in (401, 403)


def test_auth_rejects_wrong_token(api_client):
    r = api_client.get(
        "/api/v1/tests", headers={"Authorization": "Bearer wrong"},
    )
    assert r.status_code == 401


def test_create_test_with_only_filter(api_client):
    r = api_client.post(
        "/api/v1/tests",
        headers={"Authorization": "Bearer test-secret"},
        json={
            "router_endpoint": "http://127.0.0.1:1/v1",
            "api_key": "dummy",
            "only": ["D25"],
            "timeout": 5.0,
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert "task_id" in body
    assert body["status"] == "pending"
    assert body["ws_url"].startswith("/api/v1/tests/")


def test_get_test_404_for_unknown_id(api_client):
    r = api_client.get(
        "/api/v1/tests/nonexistent",
        headers={"Authorization": "Bearer test-secret"},
    )
    assert r.status_code == 404


def test_create_test_rejects_unknown_only_ids(api_client):
    """H3: invalid --only IDs should 400 immediately, not create a ghost task."""
    r = api_client.post(
        "/api/v1/tests",
        headers={"Authorization": "Bearer test-secret"},
        json={
            "router_endpoint": "http://127.0.0.1:1/v1",
            "api_key": "dummy",
            "only": ["D_BOGUS", "D_TYPO", "D25"],
        },
    )
    assert r.status_code == 400
    assert "D_BOGUS" in r.text


def test_cancel_404_vs_409(api_client):
    """M1: distinct status codes for missing (404) vs wrong state (409)."""
    r = api_client.post(
        "/api/v1/tests/nonexistent/cancel",
        headers={"Authorization": "Bearer test-secret"},
    )
    assert r.status_code == 404


def test_delete_404_for_unknown(api_client):
    r = api_client.delete(
        "/api/v1/tests/nonexistent",
        headers={"Authorization": "Bearer test-secret"},
    )
    assert r.status_code == 404


def test_timing_attack_resistance():
    """H2: auth uses hmac.compare_digest."""
    import inspect

    from src.api import auth
    source = inspect.getsource(auth.verify_token)
    assert "compare_digest" in source, "auth must use constant-time comparison"


def test_extra_headers_scrubbed_in_detail(api_client):
    """Extra headers containing Authorization/Cookie should be masked in GET /tests/{id}."""
    r = api_client.post(
        "/api/v1/tests",
        headers={"Authorization": "Bearer test-secret"},
        json={
            "router_endpoint": "http://127.0.0.1:1/v1",
            "api_key": "dummy",
            "extra_headers": {
                "Authorization": "Bearer super-secret-123",
                "X-API-Key": "another-secret",
                "X-Trace-Id": "safe-to-show",
            },
            "only": ["D25"],
        },
    )
    assert r.status_code == 200
    task_id = r.json()["task_id"]
    r2 = api_client.get(
        f"/api/v1/tests/{task_id}",
        headers={"Authorization": "Bearer test-secret"},
    )
    assert r2.status_code == 200
    headers = r2.json()["config"]["extra_headers"]
    assert headers["Authorization"] == "***"
    assert headers["X-API-Key"] == "***"
    assert headers["X-Trace-Id"] == "safe-to-show"
    assert "super-secret-123" not in r2.text
