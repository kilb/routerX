"""D111 StreamPrematureTermination -- detect prematurely closed streams.

Sends a streaming request asking for ~200 tokens. Checks whether the stream
terminated properly (has finish_reason) and produced meaningful content.
FAIL if no finish_reason AND content is extremely short (< 50 tokens).
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

MIN_CONTENT_TOKENS = 50


@detector
class D111_StreamPrematureTermination(BaseDetector):
    detector_id = "D111"
    detector_name = "StreamPrematureTermination"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = 1
    description = "Detect prematurely terminated streaming responses"

    async def send_probes(self) -> list[ProbeResponse]:
        return [await self.client.send_stream(ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "temperature": 0,
                "max_tokens": 200,
                "messages": [{"role": "user", "content": (
                    "Write a detailed paragraph about the history of the "
                    "internet, covering at least five major milestones."
                )}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="D111 premature termination probe",
        ))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r = responses[0]
        if r.is_network_error:
            return self._pass({"note": r.error or "network error"})

        body = r.body or {}
        content = body.get("full_content", "")
        finish_reason = body.get("finish_reason")
        chunk_count = body.get("chunk_count", 0)

        # Rough token estimate: word count
        word_count = len(content.split()) if content else 0

        evidence = {
            "finish_reason": finish_reason,
            "chunk_count": chunk_count,
            "word_count": word_count,
            "content_preview": (content or "")[:100],
        }

        if not finish_reason and word_count < MIN_CONTENT_TOKENS:
            # Reasoning models (o1/o3/o4) may produce zero visible words
            # when all output is in internal thinking tokens.
            model_lower = self.config.claimed_model.lower()
            if any(k in model_lower for k in ("o1", "o3", "o4", "deepseek-r1", "thinking")):
                return self._pass(evidence | {
                    "note": "reasoning model may have all output in thinking tokens",
                })
            return self._fail(
                f"stream terminated without finish_reason, only {word_count} words",
                evidence,
            )
        return self._pass(evidence)

    @classmethod
    def _test_cases(cls):
        def _stream(content: str, fr: str | None, chunks: int = 10) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={"full_content": content, "chunk_count": chunks, "finish_reason": fr, "usage": None},
            )

        return [
            ("PASS: normal stream with finish_reason",
             [_stream("The internet began in the 1960s with ARPANET. " * 5, "stop")],
             "pass"),
            ("PASS: long content even without finish_reason",
             [_stream(" ".join(["word"] * 80), None, 20)],
             "pass"),
            ("FAIL: premature termination",
             [_stream("Hello world", None, 2)],
             "fail"),
            ("PASS: network error",
             [ProbeResponse(status_code=0, error="STREAM_TIMEOUT")],
             "pass"),
        ]


if __name__ == "__main__":
    D111_StreamPrematureTermination.self_test()
