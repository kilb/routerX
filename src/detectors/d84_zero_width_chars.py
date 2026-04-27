"""D84 ZeroWidthCharDetection -- invisible Unicode tracking/watermarking.

Legitimate LLM APIs never inject zero-width or invisible Unicode characters
into generated text.  Some dishonest routers embed these codepoints to
fingerprint or watermark responses for tracking purposes.

Three distinct prompts are sent concurrently.  If ANY response contains at
least one invisible character the detector FAILs.
"""
from __future__ import annotations

import unicodedata

from ..models import (
    DetectorResult,
    JudgeMode,
    Priority,
    ProbeRequest,
    ProbeResponse,
)
from ..registry import BaseDetector, detector

_INVISIBLE_CHARS: set[str] = {
    "\u200b",  # zero-width space
    "\u200c",  # zero-width non-joiner
    "\u200d",  # zero-width joiner
    "\u200e",  # left-to-right mark
    "\u200f",  # right-to-left mark
    "\u2060",  # word joiner
    "\u2061",  # function application
    "\u2062",  # invisible times
    "\u2063",  # invisible separator
    "\u2064",  # invisible plus
    "\ufeff",  # BOM / zero-width no-break space
    "\u00ad",  # soft hyphen
    "\u034f",  # combining grapheme joiner
    "\u061c",  # Arabic letter mark
    "\u180e",  # Mongolian vowel separator
}

_PROMPTS = [
    "What is the capital of France?",
    "Name three primary colors.",
    "What is 7 times 8?",
]

_N = len(_PROMPTS)


@detector
class D84_ZeroWidthCharDetection(BaseDetector):
    detector_id = "D84"
    detector_name = "ZeroWidthCharDetection"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = _N
    description = "Detect invisible Unicode character injection for tracking/watermarking."

    async def send_probes(self) -> list[ProbeResponse]:
        probes = [
            ProbeRequest(
                payload={
                    "model": self.config.claimed_model,
                    "temperature": 0,
                    "max_tokens": 50,
                    "messages": [{"role": "user", "content": prompt}],
                },
                endpoint_path=self.config.default_endpoint_path,
                description=f"D84 zero-width probe {i}",
            )
            for i, prompt in enumerate(_PROMPTS)
        ]
        return await self.client.send_concurrent(probes)

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        findings: list[dict[str, object]] = []

        for idx, r in enumerate(responses):
            if r.is_network_error or r.status_code != 200:
                continue
            content = r.content
            if not content:
                continue
            hits: list[dict[str, object]] = []
            for pos, ch in enumerate(content):
                cp = ord(ch)
                # Variation selectors (U+FE00..U+FE0F) are part of standard
                # emoji sequences (e.g. heart emoji) and never used for
                # watermarking -- skip them entirely.
                if 0xFE00 <= cp <= 0xFE0F:
                    continue
                is_invisible = (
                    ch in _INVISIBLE_CHARS
                    or unicodedata.category(ch) == "Cf"
                    # Tag characters (U+E0000..U+E007F)
                    or 0xE0000 <= cp <= 0xE007F
                )
                if is_invisible:
                    hits.append({"position": pos, "codepoint": f"U+{cp:04X}"})
            if hits:
                findings.append({
                    "response_index": idx,
                    "invisible_char_count": len(hits),
                    "details": hits,
                })

        usable = [
            r for r in responses
            if not r.is_network_error and r.status_code == 200 and r.content
        ]
        if not usable:
            return self._pass({"note": "no usable responses with content — no evidence of issue"})

        if findings:
            total = sum(int(f["invisible_char_count"]) for f in findings)
            return self._fail(
                f"found {total} invisible character(s) across "
                f"{len(findings)} response(s)",
                {"findings": findings},
            )
        return self._pass({"checked_responses": len(usable)})

    @classmethod
    def _test_cases(cls):
        def _ok(content: str) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={
                    "choices": [
                        {"message": {"content": content}, "finish_reason": "stop"}
                    ]
                },
            )

        return [
            (
                "PASS: all clean responses",
                [
                    _ok("Paris is the capital of France."),
                    _ok("Red, blue, and yellow."),
                    _ok("56."),
                ],
                "pass",
            ),
            (
                "FAIL: zero-width space in response 1",
                [
                    _ok("Paris\u200b is the capital."),
                    _ok("Red, blue, yellow."),
                    _ok("56."),
                ],
                "fail",
            ),
            (
                "FAIL: BOM character in response 3",
                [
                    _ok("Paris is the capital."),
                    _ok("Red, blue, yellow."),
                    _ok("\ufeff56."),
                ],
                "fail",
            ),
            (
                "PASS: variation selector is standard emoji (not watermark)",
                [
                    _ok("Paris is the capital."),
                    _ok("Red\ufe0f, blue, yellow."),
                    _ok("56."),
                ],
                "pass",
            ),
            (
                "PASS: all network errors",
                [
                    ProbeResponse(status_code=0, error="TIMEOUT"),
                    ProbeResponse(status_code=0, error="TIMEOUT"),
                    ProbeResponse(status_code=0, error="TIMEOUT"),
                ],
                "pass",
            ),
        ]


if __name__ == "__main__":
    D84_ZeroWidthCharDetection.self_test()
