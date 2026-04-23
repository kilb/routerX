from __future__ import annotations

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, Capability, ApiFormat, ProbeRequest, ProbeResponse, DetectorResult
from ..assets import get_probe_pdf, to_base64

_DEFAULT_NONCE = "PDF-NONCE-MID-55K"


@detector
class D27b_PDFFidelityProbe(BaseDetector):
    detector_id = "D27b"
    detector_name = "PDFFidelityProbe"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = 1
    required_capabilities = (Capability.PDF,)
    description = "Detect PDF multimodal degradation"

    async def send_probes(self) -> list[ProbeResponse]:
        pdf_bytes, nonce = get_probe_pdf()
        self._nonce = nonce
        b64 = to_base64(pdf_bytes)
        # Use the correct PDF format based on API format:
        # - Anthropic native: type=document with source
        # - OpenAI-compatible (OpenRouter etc.): type=file with data URL
        if self.config.api_format == ApiFormat.ANTHROPIC:
            pdf_part = {
                "type": "document",
                "source": {"type": "base64", "media_type": "application/pdf", "data": b64},
            }
        else:
            pdf_part = {
                "type": "file",
                "file": {"filename": "probe.pdf", "file_data": f"data:application/pdf;base64,{b64}"},
            }
        return [await self.client.send(ProbeRequest(
            payload={"model": self.config.claimed_model, "temperature": 0, "max_tokens": 40,
                     "messages": [{"role": "user", "content": [
                         pdf_part,
                         {"type": "text", "text": "Read the PDF. Output only the nonce found on page 2. Nothing else."}]}]},
            endpoint_path=self.config.default_endpoint_path, description="pdf probe"))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error or "network error")
        if r.status_code != 200:
            return self._inconclusive(r.error_detail)
        nonce = getattr(self, "_nonce", _DEFAULT_NONCE)
        content = r.content.strip()
        if not content:
            return self._inconclusive("empty content")
        if nonce in content:
            return self._pass({"expected": nonce, "got": content})
        return self._fail("PDF nonce not found", {"expected": nonce, "got": content})

    @classmethod
    def _test_cases(cls):
        return [
            ("PASS: nonce found", [ProbeResponse(status_code=200, body={"choices": [{"message": {"content": _DEFAULT_NONCE}, "finish_reason": "stop"}]})], "pass"),
            ("FAIL: wrong nonce", [ProbeResponse(status_code=200, body={"choices": [{"message": {"content": "some other text"}, "finish_reason": "stop"}]})], "fail"),
            ("INCONCLUSIVE: network error", [ProbeResponse(status_code=0, error="TIMEOUT")], "inconclusive"),
            ("INCONCLUSIVE: empty content", [ProbeResponse(status_code=200, body={"choices": [{"message": {"content": ""}, "finish_reason": "stop"}]})], "inconclusive"),
            ("INCONCLUSIVE: non-200 status", [ProbeResponse(status_code=503, body=None)], "inconclusive"),
        ]


if __name__ == "__main__":
    D27b_PDFFidelityProbe.self_test()
