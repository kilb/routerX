from __future__ import annotations

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, Capability, ProbeRequest, ProbeResponse, DetectorResult
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
        return [await self.client.send(ProbeRequest(
            payload={"model": self.config.claimed_model, "temperature": 0, "max_tokens": 40,
                     "messages": [{"role": "user", "content": [
                         {"type": "document", "source": {"type": "base64", "media_type": "application/pdf", "data": b64}},
                         {"type": "text", "text": "Read the PDF. Output only the nonce found on page 2. Nothing else."}]}]},
            endpoint_path=self.config.default_endpoint_path, description="pdf probe"))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error or "network error")
        nonce = getattr(self, "_nonce", _DEFAULT_NONCE)
        content = r.content.strip()
        if nonce in content:
            return self._pass({"expected": nonce, "got": content})
        return self._fail("PDF nonce not found", {"expected": nonce, "got": content})

    @classmethod
    def _test_cases(cls):
        return [
            ("PASS: nonce found", [ProbeResponse(status_code=200, body={"choices": [{"message": {"content": _DEFAULT_NONCE}, "finish_reason": "stop"}]})], "pass"),
            ("FAIL: wrong nonce", [ProbeResponse(status_code=200, body={"choices": [{"message": {"content": "some other text"}, "finish_reason": "stop"}]})], "fail"),
            ("INCONCLUSIVE: network error", [ProbeResponse(status_code=0, error="TIMEOUT")], "inconclusive"),
        ]


if __name__ == "__main__":
    D27b_PDFFidelityProbe.self_test()
