"""D68 FrequencyPenaltyHonor -- detect frequency_penalty being silently dropped.

Ask for 30 repeats of 'apple'. With frequency_penalty=0 a compliant model
complies. With frequency_penalty=1.8 it cannot repeat 'apple' 30 times --
it either diversifies (inserts alternatives) or stops early. If both runs
look identical, the router dropped the parameter.
"""
from __future__ import annotations

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProviderType, ProbeRequest, ProbeResponse, DetectorResult


_WORD = "apple"
_NO_PENALTY = 0.0
_HIGH_PENALTY = 1.8


def _count_word(text: str, word: str) -> int:
    return sum(1 for w in text.lower().split() if w.strip(".,!?;:\"'") == word)


@detector
class D68_FrequencyPenaltyHonor(BaseDetector):
    detector_id = "D68"
    detector_name = "FrequencyPenaltyHonor"
    priority = Priority.P2
    judge_mode = JudgeMode.MAJORITY_2_OF_2
    request_count = 2
    detector_timeout = 60.0
    description = "Detect frequency_penalty being silently dropped."

    async def send_probes(self) -> list[ProbeResponse]:
        prompt = ("List the word 'apple' 30 times, separated by spaces. "
                  "Just the words, nothing else.")
        probes = [
            ProbeRequest(
                payload={
                    "model": self.config.claimed_model,
                    "max_tokens": 120,
                    "temperature": 0.3,
                    "frequency_penalty": penalty,
                    "messages": [{"role": "user", "content": prompt}],
                },
                endpoint_path=self.config.default_endpoint_path,
                description=f"D68 frequency_penalty={penalty}",
            )
            for penalty in (_NO_PENALTY, _HIGH_PENALTY)
        ]
        return await self.client.send_concurrent(probes)

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r_no, r_hi = responses
        for r in (r_no, r_hi):
            if r.is_network_error:
                return self._inconclusive(r.error or "network error")
            if r.status_code != 200:
                return self._inconclusive(f"status {r.status_code}")
        no_text = r_no.content or ""
        hi_text = r_hi.content or ""
        no_count = _count_word(no_text, _WORD)
        hi_count = _count_word(hi_text, _WORD)
        no_len = len(no_text)
        hi_len = len(hi_text)

        ev = {"no_penalty_apple_count": no_count,
              "high_penalty_apple_count": hi_count,
              "no_penalty_len": no_len, "high_penalty_len": hi_len}

        if no_count < 10:
            return self._inconclusive(
                f"base run only produced {no_count} 'apple's -- model didn't comply"
            )
        ratio = hi_count / no_count
        # Length collapse: high-penalty run cut off early.
        if hi_len < 0.5 * no_len:
            return self._pass(ev | {"note": "high-penalty run truncated"})
        if ratio <= 0.75:
            return self._pass(ev | {"ratio": ratio})
        len_delta = abs(hi_len - no_len) / max(no_len, 1)
        if ratio > 0.90 and len_delta < 0.20:
            # Anthropic/Gemini don't support frequency_penalty; dropping it
            # is correct proxy behavior, not fraud.
            if self.config.claimed_provider in (ProviderType.ANTHROPIC,
                                                  ProviderType.GEMINI) \
               or any(k in self.config.claimed_model.lower()
                      for k in ("claude", "gemini", "llama", "qwen", "mistral")):
                return self._inconclusive(
                    "frequency_penalty not supported by claimed provider/model"
                )
            return self._fail(
                f"high-penalty run repeated 'apple' at {ratio:.0%} of base rate "
                f"with similar length -- frequency_penalty likely dropped", ev,
            )
        return self._pass(ev | {"ratio": ratio})

    @classmethod
    def _test_cases(cls):
        def mk(content: str) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={"choices": [{"message": {"content": content},
                                   "finish_reason": "stop"}]},
            )
        repeat_30 = " ".join(["apple"] * 30)
        diversified = "apple pear banana apple grape orange"
        return [
            ("PASS: penalty honored (fewer apples)",
             [mk(repeat_30), mk(diversified)], "pass"),
            ("FAIL: penalty dropped (identical apple count, similar length)",
             [mk(repeat_30), mk(repeat_30)], "fail"),
            ("PASS: penalty truncated output early",
             [mk(repeat_30), mk("apple pear")], "pass"),
            ("INCONCLUSIVE: base didn't comply",
             [mk("I will not do that."), mk("I will not do that.")], "inconclusive"),
            ("INCONCLUSIVE: network error",
             [mk(repeat_30), ProbeResponse(status_code=0, error="T")], "inconclusive"),
        ]


if __name__ == "__main__":
    D68_FrequencyPenaltyHonor.self_test()
