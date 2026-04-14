"""D25 OutputCapProbe -- detect gateway-level max_tokens truncation.

Asks the model to repeat a chosen word a specific number of times.
Word and target count are randomized per-run so a router cannot
fingerprint the probe by prompt string match. The word is chosen from
a pool of real-looking nouns (product names, event labels) rather
than the literal "BETA" which was the original probe's tell.
"""
from __future__ import annotations

import random

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProbeRequest, ProbeResponse, DetectorResult


# Pool of short, simple, real-looking words. Chosen to be distinct from
# common English function words so counting is unambiguous.
_REPEAT_WORDS = [
    "SIGMA", "DELTA", "KAPPA", "OMEGA", "ZULU", "TANGO", "ECHO", "CHARLIE",
    "MATRIX", "NEBULA", "QUANTUM", "VERTEX", "ORBIT", "PRISM", "VOLT", "NOVA",
]

# Thresholds relative to target (as fractions, not absolute counts, so they
# scale with whatever target the run chose).
MIN_OK_FRACTION = 0.50   # < 50% of target = FAIL
HEALTHY_FRACTION = 0.875 # >= 87.5% of target + finish=stop = definite PASS

# Fixed values for self_test fallback when send_probes isn't called.
_TEST_WORD = "SIGMA"
_TEST_TARGET = 800


@detector
class D25_OutputCapProbe(BaseDetector):
    detector_id = "D25"
    detector_name = "OutputCapProbe"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = 1
    description = "Detect router secretly lowering max_tokens at gateway level"

    async def send_probes(self) -> list[ProbeResponse]:
        self._word = random.choice(_REPEAT_WORDS)
        self._target = random.choice([600, 700, 800, 900, 1000])
        return [await self.client.send(ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "max_tokens": 2048,
                "messages": [{"role": "user", "content": (
                    f"Please repeat the word '{self._word}' exactly {self._target} "
                    "times, separated by single spaces. Do not include anything else "
                    "in your response."
                )}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="output cap probe",
        ))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error or "network error")
        content = r.content
        if not content:
            return self._inconclusive("empty content")
        word = getattr(self, "_word", _TEST_WORD)
        target = getattr(self, "_target", _TEST_TARGET)
        count = content.split().count(word)
        finish_reason = r.finish_reason
        min_ok = int(target * MIN_OK_FRACTION)
        healthy = int(target * HEALTHY_FRACTION)
        ev = {
            "word": word, "target": target, "count": count,
            "finish_reason": finish_reason,
        }
        if count < min_ok and finish_reason == "length":
            return self._fail("output capped", ev)
        if count < min_ok and finish_reason == "stop":
            return self._fail("semantic truncation", ev)
        if count >= healthy and finish_reason == "stop":
            return self._pass(ev)
        # Middle zone (count between min_ok and healthy, or unusual finish): lenient PASS
        return self._pass(ev)

    @classmethod
    def _test_cases(cls):
        def make_resp(content: str, finish_reason: str,
                      status_code: int = 200) -> ProbeResponse:
            return ProbeResponse(
                status_code=status_code,
                body={"choices": [{"message": {"content": content},
                                   "finish_reason": finish_reason}]},
            )

        return [
            ("PASS: 800 words at target",
             [make_resp(" ".join([_TEST_WORD] * 800), "stop")], "pass"),
            ("FAIL: capped by router (200 words, length)",
             [make_resp(" ".join([_TEST_WORD] * 200), "length")], "fail"),
            ("FAIL: semantic truncation (100 words, stop)",
             [make_resp(" ".join([_TEST_WORD] * 100), "stop")], "fail"),
            ("INCONCLUSIVE: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT")], "inconclusive"),
            ("INCONCLUSIVE: empty content",
             [make_resp("", "stop")], "inconclusive"),
            ("PASS: exactly at min_ok (400 words)",
             [make_resp(" ".join([_TEST_WORD] * 400), "stop")], "pass"),
        ]


if __name__ == "__main__":
    D25_OutputCapProbe.self_test()
