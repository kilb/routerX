"""D92 MultiModalInputStripping -- detect image content silently stripped.

Sends a vision request with a probe image containing a known verification code.
If the router strips image data before forwarding, the model cannot identify
the code and the detector FAILs.
"""
from __future__ import annotations

from ..assets import get_probe_image, to_data_url
from ..models import (
    Capability,
    DetectorResult,
    JudgeMode,
    Priority,
    ProbeRequest,
    ProbeResponse,
)
from ..registry import BaseDetector, detector

_TEST_CODE = "XK9Z4P"
MIN_SUBSTANTIVE_LEN = 10


@detector
class D92_MultiModalInputStripping(BaseDetector):
    detector_id = "D92"
    detector_name = "MultiModalInputStripping"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = 1
    required_capabilities = (Capability.VISION,)
    description = "Detect image content silently stripped from vision requests"

    async def send_probes(self) -> list[ProbeResponse]:
        img_bytes, code = get_probe_image()
        self._code = code
        data_url = to_data_url(img_bytes, "image/png")
        return [await self.client.send(ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "temperature": 0,
                "max_tokens": 30,
                "messages": [{"role": "user", "content": [
                    {"type": "image_url", "image_url": {"url": data_url, "detail": "high"}},
                    {"type": "text", "text": "What is the verification code shown in this image? Reply with only the code."},
                ]}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description=f"D92 multimodal input strip probe code={code}",
        ))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error or "network error")
        if r.status_code != 200:
            return self._inconclusive(f"status {r.status_code}")

        content = r.content.strip()
        if not content:
            return self._inconclusive("empty content")

        code = getattr(self, "_code", _TEST_CODE)
        evidence = {"expected_code": code, "response": content[:200]}

        if code in content:
            return self._pass(evidence)

        # Fuzzy match: OCR may misread some chars but model IS seeing the image
        import re
        found = re.findall(r'\b[A-Za-z0-9]{4,8}\b', content)
        if found and code:
            for fc in found:
                if len(fc) == len(code):
                    diffs = sum(1 for a, b in zip(fc.upper(), code.upper()) if a != b)
                    if diffs <= 3:
                        return self._pass(evidence | {"fuzzy_match": fc})

        if len(content) > MIN_SUBSTANTIVE_LEN:
            return self._fail("image code not found -- image may be stripped", evidence)

        return self._inconclusive("response too short to determine")

    @classmethod
    def _test_cases(cls):
        def _resp(content: str) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={"choices": [{"message": {"role": "assistant", "content": content}, "finish_reason": "stop"}]},
            )

        return [
            ("PASS: code found",
             [_resp(_TEST_CODE)],
             "pass"),
            ("FAIL: image stripped, wrong answer",
             [_resp("I can see text but no verification code.")],
             "fail"),
            ("INCONCLUSIVE: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT")],
             "inconclusive"),
            ("INCONCLUSIVE: empty content",
             [_resp("")],
             "inconclusive"),
        ]


if __name__ == "__main__":
    D92_MultiModalInputStripping.self_test()
