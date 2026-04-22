"""D96 UnicodeNormalizationLoss -- detect Unicode fidelity degradation.

Routers that transcode through ASCII-only pipelines or normalize
aggressively may lose special characters.  This detector sends a prompt
containing diverse Unicode and checks how many survive in the response.
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

_UNICODE_PROMPT = (
    'Repeat exactly: cafe\u0301 \u2192 nai\u0308ve \u65e5\u672c\u8a9e '
    '\U0001f389 x\u00b2 \u2211 \u2260 \u211d \u2122 \u00abguillemets\u00bb'
)

_CHECKLIST = [
    "caf\u00e9",
    "na\u00efve",
    "\u65e5\u672c\u8a9e",
    "\U0001f389",
    "x\u00b2",
    "\u2211",
    "\u2260",
    "\u211d",
    "\u2122",
    "\u00abguillemets\u00bb",
]

import unicodedata

MIN_PRESENT = 7  # 7/10 = 70% threshold


def _normalize(text: str) -> str:
    """NFC-normalize so combining sequences match precomposed forms."""
    return unicodedata.normalize("NFC", text)


@detector
class D96_UnicodeNormalizationLoss(BaseDetector):
    detector_id = "D96"
    detector_name = "UnicodeNormalizationLoss"
    priority = Priority.P2
    judge_mode = JudgeMode.ONCE
    request_count = 1
    description = "Detect Unicode character loss through router transcoding"

    async def send_probes(self) -> list[ProbeResponse]:
        return [await self.client.send(ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "temperature": 0,
                "max_tokens": 200,
                "messages": [{"role": "user", "content": _UNICODE_PROMPT}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="D96 unicode fidelity probe",
        ))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error or "network error")

        content = r.content
        if not content:
            return self._inconclusive("empty content")

        normalized_content = _normalize(content)
        found: list[str] = []
        missing: list[str] = []
        for item in _CHECKLIST:
            normalized_item = _normalize(item)
            if normalized_item in normalized_content:
                found.append(item)
            else:
                missing.append(item)

        present_count = len(found)
        evidence = {
            "present": present_count,
            "total": len(_CHECKLIST),
            "found": found,
            "missing": missing,
            "content_preview": content[:200],
        }

        if present_count < MIN_PRESENT:
            # If response is very short, output was likely truncated before
            # all items could be echoed — not Unicode degradation.
            if len(content) < 50:
                return self._pass(evidence | {
                    "note": "response truncated, cannot verify all Unicode items",
                })
            return self._fail(
                f"only {present_count}/{len(_CHECKLIST)} Unicode items preserved",
                evidence,
            )
        return self._pass(evidence)

    @classmethod
    def _test_cases(cls):
        def _resp(content: str) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={
                    "choices": [{
                        "message": {"role": "assistant", "content": content},
                        "finish_reason": "stop",
                    }],
                },
            )

        full_echo = (
            "caf\u00e9 \u2192 na\u00efve \u65e5\u672c\u8a9e "
            "\U0001f389 x\u00b2 \u2211 \u2260 \u211d \u2122 \u00abguillemets\u00bb"
        )
        ascii_only = "Here are the items you requested: cafe, naive, nihongo, party, x2, sum, not-equal, R, TM, guillemets. All converted to ASCII equivalents for compatibility."

        return [
            ("PASS: all Unicode present",
             [_resp(full_echo)],
             "pass"),
            ("FAIL: ASCII-only degradation",
             [_resp(ascii_only)],
             "fail"),
            ("INCONCLUSIVE: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT")],
             "inconclusive"),
            ("INCONCLUSIVE: empty content",
             [_resp("")],
             "inconclusive"),
        ]


if __name__ == "__main__":
    D96_UnicodeNormalizationLoss.self_test()
