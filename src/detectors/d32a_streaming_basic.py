from __future__ import annotations

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProviderType, ProbeRequest, ProbeResponse, DetectorResult
from ..utils.timing import analyze_chunks

MIN_CHUNKS = 3
MAX_LAST_CHUNK_RATIO = 0.8


@detector
class D32a_StreamingBasicProbe(BaseDetector):
    detector_id = "D32a"
    detector_name = "StreamingBasicProbe"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = 1
    description = "Detect fake streaming (non-stream result split into chunks)"

    async def send_probes(self) -> list[ProbeResponse]:
        return [await self.client.send_stream(ProbeRequest(
            payload={"model": self.config.claimed_model, "temperature": 0, "max_tokens": 220,
                     "stream": True, "stream_options": {"include_usage": True},
                     "messages": [{"role": "user", "content": "Output the numbers from 1 to 120, one per line, and nothing else."}]},
            endpoint_path=self.config.default_endpoint_path, description="streaming probe"))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r = responses[0]
        if r.is_network_error:
            return self._pass({"note": r.error or "network error"})
        body = r.body or {}
        chunk_count = body.get("chunk_count", 0)
        usage = body.get("usage")
        finish = body.get("finish_reason")
        timing = analyze_chunks(r.chunk_timestamps)
        ev = {"chunk_count": chunk_count, "has_usage": usage is not None, "finish_reason": finish, "timing": timing}
        if chunk_count == 0:
            # Zero chunks may indicate SSE parsing failure (non-standard
            # format), not fake streaming. Cannot determine.
            return self._pass({"note": "0 chunks received -- may be SSE parsing issue"})
        if chunk_count <= 2:
            # Short responses (< 20 tokens) legitimately arrive in 1-2 chunks.
            # Only flag when the response is substantive (many tokens) but
            # still arrives in just 1-2 chunks — that's fake streaming.
            full_content = body.get("full_content", "") or ""
            if len(full_content.split()) < 20:
                return self._pass({**ev, "note": f"only {chunk_count} chunks but short response — not suspicious"})
            return self._fail(f"only {chunk_count} chunks for substantive response: likely fake streaming", ev)
        # Check content distribution
        if r.chunks and len(r.chunks) > 2:
            total_len = sum(len(self._chunk_content(c)) for c in r.chunks)
            last_len = len(self._chunk_content(r.chunks[-1]))
            if total_len > 0 and last_len / total_len > MAX_LAST_CHUNK_RATIO:
                return self._fail("80%+ content in last chunk", {**ev, "last_ratio": last_len / total_len})
        # stream_options.include_usage is an OpenAI-native feature.
        # Many legitimate routers/providers (Anthropic, Gemini, Bedrock,
        # open-source backends) don't return usage in streaming mode.
        # Missing usage alone is not evidence of fake streaming.
        if usage is not None:
            ev["has_usage"] = True
        return self._pass(ev)

    @staticmethod
    def _chunk_content(chunk: dict) -> str:
        try:
            c = chunk.get("choices", [{}])[0].get("delta", {}).get("content")
            return c if c is not None else ""
        except (KeyError, IndexError):
            return ""

    @classmethod
    def _test_cases(cls):
        # Stream body format from send_stream
        def stream_body(content: str, chunks: int, usage: dict | None, fr: str = "stop") -> dict:
            return {"full_content": content, "chunk_count": chunks, "finish_reason": fr, "usage": usage}
        small_chunks = [{"choices": [{"delta": {"content": str(i)}}]} for i in range(50)]
        big_last = [
            {"choices": [{"delta": {"content": "x"}}]},
            {"choices": [{"delta": {"content": "x"}}]},
            {"choices": [{"delta": {"content": "y" * 1000}}]},
        ]
        return [
            ("PASS: normal stream", [ProbeResponse(status_code=200, body=stream_body("1\n2\n3", 50, {"total_tokens": 60}),
                                                    chunks=small_chunks, chunk_timestamps=[i * 0.1 for i in range(50)])], "pass"),
            ("FAIL: only 2 chunks for long response", [ProbeResponse(status_code=200, body=stream_body(" ".join(str(i) for i in range(100)), 2, {"total_tokens": 100}),
                                                    chunks=[{}, {}], chunk_timestamps=[0.1, 0.2])], "fail"),
            ("FAIL: 80% in last chunk", [ProbeResponse(status_code=200, body=stream_body("xx" + "y" * 1000, 3, {"total_tokens": 10}),
                                                        chunks=big_last, chunk_timestamps=[0.1, 0.2, 0.3])], "fail"),
            ("PASS: no usage block (legitimate for non-OpenAI)", [ProbeResponse(status_code=200, body=stream_body("1\n2\n3", 50, None),
                                                     chunks=small_chunks, chunk_timestamps=[i * 0.1 for i in range(50)])], "pass"),
            ("PASS: network error", [ProbeResponse(status_code=0, error="TIMEOUT")], "pass"),
        ]


if __name__ == "__main__":
    D32a_StreamingBasicProbe.self_test()
