"""D41 BehavioralFingerprint -- detect model-family substitution via
statistical signatures of random-generation tasks.

Complements D4a (tokenizer-boundary fingerprint) with orthogonal
evidence: the *output distribution* of pseudo-random tasks. Bare
open-source models (especially small ones) have dramatically lower
entropy than frontier models on "generate 100 random digits" tasks.

This is probabilistic, not deterministic -- we use thresholds calibrated
to empirical differences between frontier models and bare open-source
models on simple random-generation tasks.
"""
from __future__ import annotations

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProbeRequest, ProbeResponse, DetectorResult
from ..utils.stats import digit_stats


# HEURISTIC thresholds — empirical calibration TODO.
# Conservatively set to avoid false positives on small frontier models
# (claude-3-haiku, gpt-4o-mini, gemini-flash can legitimately land in
# the 2.6-3.1 entropy band). Earlier 3.0 threshold risked flagging
# legitimate Haiku-class models as "bare".
#
# TODO: calibrate per model family with a reference distribution (KS
# against a baseline captured from the real API). Until then this is a
# PROBABILISTIC heuristic — MAJORITY_2_OF_2 reduces single-sample variance.
MIN_FRONTIER_ENTROPY = 2.6
MAX_FRONTIER_SINGLE_DIGIT_COUNT = 25


@detector
class D41_BehavioralFingerprint(BaseDetector):
    detector_id = "D41"
    detector_name = "BehavioralFingerprint"
    priority = Priority.P0
    # MAJORITY_2_OF_2: temperature=1.0 makes this stochastic. One unlucky
    # sample should not fail the detector — require 2/2 runs to agree.
    judge_mode = JudgeMode.MAJORITY_2_OF_2
    request_count = 1
    detector_timeout = 45.0
    description = (
        "Detect model-family substitution via entropy of random-digit "
        "generation (complements D4a tokenizer fingerprint)."
    )

    async def send_probes(self) -> list[ProbeResponse]:
        prompt = (
            "Simulate rolling a fair 10-sided die 100 times. "
            "Output exactly 100 digits from 0-9, separated by spaces, "
            "on a single line. No other text, no numbering, no headers."
        )
        return [await self.client.send(ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "max_tokens": 400,
                "temperature": 1.0,
                "messages": [{"role": "user", "content": prompt}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="D41 random digits",
        ))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error or "network error")
        stats = digit_stats(r.content)
        ev = {"stats": stats, "sample": r.content[:200]}

        if stats["count"] < 50:
            return self._inconclusive(
                f"only {stats['count']} digits extracted -- model didn't comply",
            )
        if stats["entropy"] < MIN_FRONTIER_ENTROPY:
            return self._fail(
                f"low entropy ({stats['entropy']:.2f} < {MIN_FRONTIER_ENTROPY}) "
                f"-- suggests small/bare model, not claimed frontier model",
                ev,
            )
        if stats["max_count"] > MAX_FRONTIER_SINGLE_DIGIT_COUNT:
            return self._fail(
                f"digit {stats['max_digit']} appears {stats['max_count']} times "
                f"(> {MAX_FRONTIER_SINGLE_DIGIT_COUNT}) -- suggests mode collapse",
                ev,
            )
        return self._pass(ev)

    @classmethod
    def _test_cases(cls):
        def mk(digits: str) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={"choices": [{"message": {"content": digits},
                                   "finish_reason": "stop"}]},
            )

        # Local RNG — never touches global random state (avoids flakiness
        # when earlier tests in the same run consumed random).
        import random as _random
        rng = _random.Random(42)
        uniform_100 = " ".join(str(rng.randint(0, 9)) for _ in range(100))

        skewed_100 = " ".join(
            ["7"] * 40 + [str(rng.randint(0, 9)) for _ in range(60)]
        )

        monotonic = " ".join(["3"] * 100)

        sparse = "I'm sorry, I can't output exactly 100 digits. Here are some: 1 2 3 4 5"

        return [
            ("PASS: uniform 100 digits", [mk(uniform_100)], "pass"),
            ("FAIL: heavily skewed (max_count 40)", [mk(skewed_100)], "fail"),
            ("FAIL: monotonic (entropy 0)", [mk(monotonic)], "fail"),
            ("INCONCLUSIVE: too few digits", [mk(sparse)], "inconclusive"),
            ("INCONCLUSIVE: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT")], "inconclusive"),
        ]


if __name__ == "__main__":
    D41_BehavioralFingerprint.self_test()
