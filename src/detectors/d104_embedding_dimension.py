"""D104 EmbeddingDimensionVerify -- verify embedding vector dimensions.

Sends a request to /v1/embeddings and checks that the returned vector
dimension matches the expected size for the claimed model.  Only runs
when the claimed model name contains "embedding".

A dishonest router might silently substitute a cheaper embedding model
with different dimensionality.
"""
from __future__ import annotations

from ..models import (
    DetectorResult,
    JudgeMode,
    Priority,
    ProbeRequest,
    ProbeResponse,
)
from ..registry import BaseDetector, detector

_KNOWN_DIMS: dict[str, int] = {
    "text-embedding-3-small": 1536,
    "text-embedding-3-large": 3072,
    "text-embedding-ada-002": 1536,
    "text-embedding-ada": 1536,
}


@detector
class D104_EmbeddingDimensionVerify(BaseDetector):
    detector_id = "D104"
    detector_name = "EmbeddingDimensionVerify"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = 1
    description = "Verify embedding vector dimensions match claimed model"

    async def send_probes(self) -> list[ProbeResponse]:
        model = self.config.claimed_model.lower()
        if "embedding" not in model:
            return []

        return [await self.client.send(ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "input": "Hello world",
            },
            endpoint_path="/v1/embeddings",
            description="D104 embedding dimension probe",
        ))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        if not responses:
            return self._skip("claimed model is not an embedding model")

        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error or "network error")
        if r.status_code != 200:
            return self._inconclusive(r.error_detail)
        if not r.body:
            return self._inconclusive("empty response body")

        # Extract embedding vector
        try:
            embedding = r.body["data"][0]["embedding"]
        except (KeyError, IndexError, TypeError):
            return self._inconclusive("unexpected response format -- no embedding data")

        if not isinstance(embedding, list):
            return self._inconclusive("embedding is not a list")

        actual_dim = len(embedding)
        model_key = self.config.claimed_model.lower()
        if "/" in model_key:
            model_key = model_key.rsplit("/", 1)[-1]
        expected_dim = _KNOWN_DIMS.get(model_key)

        evidence = {
            "claimed_model": self.config.claimed_model,
            "actual_dimension": actual_dim,
            "expected_dimension": expected_dim,
        }

        if expected_dim is None:
            return self._inconclusive(
                f"model {self.config.claimed_model!r} not in known dimension table"
            )

        if actual_dim != expected_dim:
            return self._fail(
                f"dimension {actual_dim} != expected {expected_dim} for "
                f"{self.config.claimed_model}",
                evidence,
            )
        return self._pass(evidence)

    @classmethod
    def _test_cases(cls):
        def _embed_resp(dim: int) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={
                    "data": [{"embedding": [0.1] * dim, "index": 0}],
                    "model": "text-embedding-3-small",
                    "usage": {"prompt_tokens": 2, "total_tokens": 2},
                },
            )

        return [
            ("PASS: correct dimension 1536",
             [_embed_resp(1536)],
             "pass"),
            ("FAIL: wrong dimension 768",
             [_embed_resp(768)],
             "fail"),
            ("INCONCLUSIVE: no embedding data",
             [ProbeResponse(status_code=200, body={"data": []})],
             "inconclusive"),
            ("INCONCLUSIVE: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT")],
             "inconclusive"),
            ("SKIP: not an embedding model",
             [],
             "skip"),
        ]

    @classmethod
    def self_test(cls) -> None:
        """Custom self_test: must use an embedding model name."""
        from unittest.mock import MagicMock
        from ..models import ProviderType
        cases = cls._test_cases()
        if not cases:
            print(f"[WARN] {cls.detector_id}: no test cases")
            return
        passed = 0
        for name, mock_resps, expected in cases:
            inst = cls.__new__(cls)
            inst.config = MagicMock()
            inst.client = MagicMock()
            inst.events = MagicMock()
            inst.shared = {}
            inst.config.claimed_model = "text-embedding-3-small"
            inst.config.claimed_provider = ProviderType.ANY
            r = inst.judge(mock_resps)
            if r.verdict.value == expected:
                passed += 1
                print(f"  [OK] {name}")
            else:
                print(f"  [FAIL] {name}: expected {expected}, got {r.verdict.value}")
        mark = "OK" if passed == len(cases) else "FAIL"
        print(f"[{mark}] {cls.detector_id}: {passed}/{len(cases)}")


if __name__ == "__main__":
    D104_EmbeddingDimensionVerify.self_test()
