from __future__ import annotations

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, Capability, ProbeRequest, ProbeResponse, DetectorResult
from ..assets import get_nonce_image, to_data_url
from ..utils.realistic_prompts import image_label

_TEST_NONCE_1 = "P/N-TESTAA-a"
_TEST_NONCE_2 = "P/N-TESTBB-b"


@detector
class D27c_MultiImageOrderProbe(BaseDetector):
    detector_id = "D27c"
    detector_name = "MultiImageOrderProbe"
    priority = Priority.P1
    judge_mode = JudgeMode.MAJORITY_2_OF_2
    request_count = 2
    required_capabilities = (Capability.VISION,)
    description = "Detect multi-image order scrambling or single-image degradation"

    async def send_probes(self) -> list[ProbeResponse]:
        self._nonce_1 = image_label("a")
        self._nonce_2 = image_label("b")
        img1 = get_nonce_image(self._nonce_1)
        img2 = get_nonce_image(self._nonce_2)
        url1, url2 = to_data_url(img1, "image/png"), to_data_url(img2, "image/png")
        return [await self.client.send(ProbeRequest(
            payload={"model": self.config.claimed_model, "temperature": 0, "max_tokens": 20,
                     "messages": [{"role": "user", "content": [
                         {"type": "text", "text": "Read the product code printed on the SECOND image. Output only the code (including the -a or -b suffix). Nothing else."},
                         {"type": "image_url", "image_url": {"url": url1}},
                         {"type": "image_url", "image_url": {"url": url2}}]}]},
            endpoint_path=self.config.default_endpoint_path, description="multi-image order"))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error or "network error")
        n1 = getattr(self, "_nonce_1", _TEST_NONCE_1)
        n2 = getattr(self, "_nonce_2", _TEST_NONCE_2)
        content = r.content.strip()
        # Extract the unique part of each nonce (after "P/N-" prefix)
        # to handle OCR that drops the prefix
        n2_core = n2.split("-", 1)[-1] if "-" in n2 else n2
        n1_core = n1.split("-", 1)[-1] if "-" in n1 else n1
        if n2 in content or n2_core in content:
            return self._pass({"expected": n2, "got": content})
        if n1 in content or n1_core in content:
            return self._fail("returned first image nonce (order scrambled)", {"expected": n2, "got": content})
        return self._fail("neither nonce recognized", {"expected": n2, "got": content})

    @classmethod
    def _test_cases(cls):
        return [
            ("PASS: second nonce returned", [ProbeResponse(status_code=200, body={"choices": [{"message": {"content": _TEST_NONCE_2}, "finish_reason": "stop"}]})], "pass"),
            ("FAIL: first nonce returned", [ProbeResponse(status_code=200, body={"choices": [{"message": {"content": _TEST_NONCE_1}, "finish_reason": "stop"}]})], "fail"),
            ("FAIL: neither nonce", [ProbeResponse(status_code=200, body={"choices": [{"message": {"content": "cannot read"}, "finish_reason": "stop"}]})], "fail"),
            ("INCONCLUSIVE: network error", [ProbeResponse(status_code=0, error="TIMEOUT")], "inconclusive"),
        ]


if __name__ == "__main__":
    D27c_MultiImageOrderProbe.self_test()
