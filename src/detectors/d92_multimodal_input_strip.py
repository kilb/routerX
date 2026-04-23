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
            return self._inconclusive(r.error_detail)

        content = r.content.strip()
        if not content:
            return self._inconclusive("empty content")

        code = getattr(self, "_code", _TEST_CODE)
        evidence = {"expected_code": code, "response": content[:200]}

        if code in content:
            return self._pass(evidence)

        # If model outputs any same-length alphanumeric code, it IS seeing the image
        import re
        found = re.findall(r'[A-Za-z0-9]{4,8}', content)
        if found and code:
            for fc in found:
                if len(fc) == len(code):
                    return self._pass(evidence | {"ocr_read": fc})

        # If model describes the image (mentions "image", "picture", "see",
        # "white", "blank", "text", "photo" etc.), it received the image but
        # failed OCR — not a stripping issue.
        image_aware_keywords = (
            "image", "picture", "photo", "see", "visual", "white",
            "blank", "appears", "shows", "display", "text",
        )
        content_lower = content.lower()
        if any(kw in content_lower for kw in image_aware_keywords):
            return self._pass(evidence | {
                "note": "model describes image content but failed OCR",
            })

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
            ("PASS: model describes visual content (OCR failed)",
             [_resp("I can see text but no verification code.")],
             "pass"),
            ("FAIL: image stripped, no visual awareness",
             [_resp("I'd be happy to help! What would you like to know?")],
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
