from __future__ import annotations

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, Capability, ProbeRequest, ProbeResponse, DetectorResult
from ..assets import get_probe_image, to_data_url

_TEST_CODE = "XK9Z4P"


@detector
class D27_ImageFidelityProbe(BaseDetector):
    detector_id = "D27"
    detector_name = "ImageFidelityProbe"
    priority = Priority.P1
    judge_mode = JudgeMode.MAJORITY_2_OF_2
    request_count = 2
    required_capabilities = (Capability.VISION,)
    description = "Detect image multimodal compression degradation"

    async def send_probes(self) -> list[ProbeResponse]:
        img_bytes, code = get_probe_image()
        self._code = code
        data_url = to_data_url(img_bytes, "image/png")
        return [await self.client.send(ProbeRequest(
            payload={"model": self.config.claimed_model, "temperature": 0, "max_tokens": 20,
                     "messages": [{"role": "user", "content": [
                         {"type": "image_url", "image_url": {"url": data_url, "detail": "high"}},
                         {"type": "text", "text": "There is a tiny text code in the bottom-right corner. Read it exactly and output only the code."}]}]},
            endpoint_path=self.config.default_endpoint_path, description=f"image probe code={code}"))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error or "network error")
        code = getattr(self, "_code", _TEST_CODE)
        content = r.content.strip()
        if code and code in content:
            return self._pass({"expected": code, "got": content})
        return self._fail("image code not recognized", {"expected": code, "got": content})

    @classmethod
    def _test_cases(cls):
        return [
            ("PASS: code recognized", [ProbeResponse(status_code=200, body={"choices": [{"message": {"content": _TEST_CODE}, "finish_reason": "stop"}]})], "pass"),
            ("FAIL: wrong code", [ProbeResponse(status_code=200, body={"choices": [{"message": {"content": "WRONG"}, "finish_reason": "stop"}]})], "fail"),
            ("INCONCLUSIVE: network error", [ProbeResponse(status_code=0, error="TIMEOUT")], "inconclusive"),
        ]


if __name__ == "__main__":
    D27_ImageFidelityProbe.self_test()
