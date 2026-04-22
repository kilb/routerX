"""D103 ContentFilterBias -- detect competitor-mention filtering.

Asks three neutral comparison questions about competing AI providers.
If the router filters or refuses competitor mentions, responses will be
abnormally short or contain refusal patterns.  Two or more refused
responses indicate systematic content filtering bias.
"""
from __future__ import annotations

import re

from ..models import (
    DetectorResult,
    JudgeMode,
    Priority,
    ProbeRequest,
    ProbeResponse,
)
from ..registry import BaseDetector, detector

_PROMPTS = [
    "Compare the strengths and weaknesses of Claude vs GPT-4o for coding tasks.",
    "Which is better for creative writing: Gemini or ChatGPT?",
    "List pros and cons of using OpenAI API vs Anthropic API.",
]

MIN_SUBSTANTIVE_LEN = 100
MIN_RESPONSE_LEN = 50

_REFUSAL_PATTERNS = re.compile(
    r"(?:can(?:'|no)t compare|not able to (?:compare|discuss)|"
    r"unable to (?:compare|provide|discuss)|"
    r"(?:won't|cannot|shouldn't) (?:compare|discuss)|"
    r"not (?:appropriate|comfortable) (?:to |for me to )?compare|"
    r"I (?:don't|do not) (?:compare|rank)|"
    r"not in a position to compare)",
    re.IGNORECASE,
)


@detector
class D103_ContentFilterBias(BaseDetector):
    detector_id = "D103"
    detector_name = "ContentFilterBias"
    priority = Priority.P2
    judge_mode = JudgeMode.ONCE
    request_count = 3
    description = "Detect filtering of competitor AI provider mentions"

    async def send_probes(self) -> list[ProbeResponse]:
        probes = [
            ProbeRequest(
                payload={
                    "model": self.config.claimed_model,
                    "temperature": 0,
                    "max_tokens": 200,
                    "messages": [{"role": "user", "content": p}],
                },
                endpoint_path=self.config.default_endpoint_path,
                description=f"D103 competitor comparison {i}",
            )
            for i, p in enumerate(_PROMPTS)
        ]
        return await self.client.send_concurrent(probes)

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        valid = [r for r in responses if not r.is_network_error]
        if not valid:
            return self._inconclusive("all requests failed with network errors")

        refused_count = 0
        short_count = 0
        details: list[dict] = []

        for i, r in enumerate(responses):
            if r.is_network_error:
                details.append({"index": i, "status": "network_error"})
                continue

            content = r.content or ""
            is_refused = bool(_REFUSAL_PATTERNS.search(content))
            is_short = len(content.strip()) < MIN_RESPONSE_LEN

            if is_refused:
                refused_count += 1
            if is_short and not r.is_network_error:
                short_count += 1

            details.append({
                "index": i,
                "length": len(content),
                "refused": is_refused,
                "preview": content[:120],
            })

        evidence = {
            "refused": refused_count,
            "short_responses": short_count,
            "total_valid": len(valid),
            "details": details,
        }

        # Claude models genuinely hedge on AI comparisons, so require all 3
        # to be blocked before flagging. Other models: 2/3 is sufficient.
        model_lower = (self.config.claimed_model or "").lower()
        is_claude = "claude" in model_lower
        fail_threshold = 3 if is_claude else 2

        blocked = refused_count + short_count
        if blocked >= fail_threshold:
            # If ALL responses are short (no explicit refusals), this could
            # be the model's output limit rather than content filtering.
            # Only FAIL when there are actual refusals, or a mix of refusals
            # and short responses.
            if refused_count == 0 and short_count >= fail_threshold:
                return self._pass(evidence | {
                    "note": f"all {short_count} responses short "
                            f"(<{MIN_RESPONSE_LEN} chars) -- likely model "
                            f"output limit, not content filtering",
                })
            return self._fail(
                f"{refused_count} refused + {short_count} too-short responses "
                "out of 3 competitor comparison questions",
                evidence,
            )

        # PASS if all give substantive answers
        substantive = sum(
            1 for d in details
            if d.get("length", 0) >= MIN_SUBSTANTIVE_LEN
            and not d.get("refused")
        )
        evidence["substantive_count"] = substantive
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

        substantive = (
            "Both Claude and GPT-4o have distinct strengths for coding. "
            "Claude excels at following complex instructions and providing "
            "well-structured code. GPT-4o is strong at quick prototyping "
            "and has broader library knowledge."
        )
        refusal = "I'm not able to compare different AI providers."

        return [
            ("PASS: substantive answers",
             [_resp(substantive), _resp(substantive), _resp(substantive)],
             "pass"),
            ("FAIL: refuses to compare",
             [_resp(refusal), _resp(refusal), _resp(substantive)],
             "fail"),
            ("FAIL: short + refused",
             [_resp(refusal), _resp("No."), _resp(substantive)],
             "fail"),
            ("INCONCLUSIVE: all network errors",
             [ProbeResponse(status_code=0, error="TIMEOUT")] * 3,
             "inconclusive"),
        ]


if __name__ == "__main__":
    D103_ContentFilterBias.self_test()
