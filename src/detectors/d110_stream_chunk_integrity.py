"""D110 StreamChunkIntegrity -- detect content divergence between stream/non-stream.

Sends the same prompt with seed=42, temp=0 twice: once non-streaming, once
streaming. Compares the two outputs via Jaccard word similarity. If they
diverge significantly, the streaming layer is modifying content.
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

JACCARD_PASS_THRESHOLD = 0.90
JACCARD_FAIL_THRESHOLD = 0.50


def _jaccard_words(a: str, b: str) -> float:
    sa = set(a.lower().split())
    sb = set(b.lower().split())
    union = sa | sb
    if not union:
        return 1.0
    return len(sa & sb) / len(union)


@detector
class D110_StreamChunkIntegrity(BaseDetector):
    detector_id = "D110"
    detector_name = "StreamChunkIntegrity"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = 2
    description = "Detect content divergence between streaming and non-streaming responses"

    async def send_probes(self) -> list[ProbeResponse]:
        payload = {
            "model": self.config.claimed_model,
            "temperature": 0,
            "seed": 42,
            "max_tokens": 80,
            "messages": [{"role": "user", "content": "What is the capital of France? Reply in one sentence."}],
        }
        non_stream = await self.client.send(ProbeRequest(
            payload=payload,
            endpoint_path=self.config.default_endpoint_path,
            description="D110 non-stream",
        ))
        stream = await self.client.send_stream(ProbeRequest(
            payload=payload,
            endpoint_path=self.config.default_endpoint_path,
            description="D110 stream",
        ))
        return [non_stream, stream]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        non_stream, stream = responses[0], responses[1]
        if non_stream.is_network_error or non_stream.status_code >= 400:
            return self._inconclusive(non_stream.error or "non-stream network error")
        if stream.is_network_error or stream.status_code >= 400:
            return self._inconclusive(stream.error or "stream network error")

        c_ns = non_stream.content
        c_s = stream.content
        if not c_ns or not c_s:
            return self._inconclusive("empty content in one or both responses")

        # Strip thinking/reasoning tags before comparison — thinking models
        # produce different reasoning traces even with identical parameters.
        import re
        c_ns_clean = re.sub(r"<think>.*?</think>", "", c_ns, flags=re.DOTALL).strip()
        c_s_clean = re.sub(r"<think>.*?</think>", "", c_s, flags=re.DOTALL).strip()
        # If all content was inside thinking tags, use originals
        if not c_ns_clean or not c_s_clean:
            c_ns_clean = c_ns
            c_s_clean = c_s

        jaccard = _jaccard_words(c_ns_clean, c_s_clean)
        evidence = {
            "non_stream_preview": c_ns[:120],
            "stream_preview": c_s[:120],
            "jaccard": f"{jaccard:.3f}",
        }

        if jaccard < JACCARD_FAIL_THRESHOLD:
            return self._fail(
                f"stream/non-stream divergence: Jaccard {jaccard:.3f} < {JACCARD_FAIL_THRESHOLD}",
                evidence,
            )
        return self._pass(evidence)

    @classmethod
    def _test_cases(cls):
        def _resp(content: str) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={"choices": [{"message": {"role": "assistant", "content": content}, "finish_reason": "stop"}]},
            )

        def _stream_resp(content: str) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={"full_content": content, "chunk_count": 5, "finish_reason": "stop", "usage": None},
            )

        return [
            ("PASS: identical content",
             [_resp("Paris is the capital of France."), _stream_resp("Paris is the capital of France.")],
             "pass"),
            ("FAIL: completely different content",
             [_resp("Paris is the capital of France."), _stream_resp("Bananas are yellow tropical fruits grown worldwide.")],
             "fail"),
            ("INCONCLUSIVE: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT"), _stream_resp("ok")],
             "inconclusive"),
            ("INCONCLUSIVE: empty content",
             [_resp(""), _stream_resp("Paris")],
             "inconclusive"),
        ]


if __name__ == "__main__":
    D110_StreamChunkIntegrity.self_test()
