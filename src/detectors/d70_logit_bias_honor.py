"""D70 LogitBiasHonor -- verify logit_bias parameter is applied.

Two runs of the same prose prompt: one plain, one with logit_bias suppressing
the token ' the' to -100. Genuine: suppressed run has near-zero occurrences.
Fraud: router drops logit_bias -> both runs show natural 'the' frequency.
"""
from __future__ import annotations

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProviderType, ProbeRequest, ProbeResponse, DetectorResult
from ..tokenizer import token_counter


def _count_the(text: str) -> int:
    return sum(1 for w in text.lower().split() if w == "the")


@detector
class D70_LogitBiasHonor(BaseDetector):
    detector_id = "D70"
    detector_name = "LogitBiasHonor"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = 2
    detector_timeout = 60.0
    description = "Detect logit_bias being silently dropped."

    async def send_probes(self) -> list[ProbeResponse]:
        model = self.config.claimed_model
        tid = token_counter.get_token_id(" the", model=model)
        if tid is None:
            self._skip_reason = f"tokenizer for {model!r} has no id for ' the'"
            return []
        prompt = ("Write a 150-word paragraph about the history of the "
                  "library of Alexandria. Natural prose, no lists.")
        base = await self.client.send(ProbeRequest(
            payload={
                "model": model,
                "max_tokens": 200,
                "temperature": 0.3,
                "messages": [{"role": "user", "content": prompt}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="D70 base (no bias)",
        ))
        biased = await self.client.send(ProbeRequest(
            payload={
                "model": model,
                "max_tokens": 200,
                "temperature": 0.3,
                "logit_bias": {str(tid): -100},
                "messages": [{"role": "user", "content": prompt}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="D70 biased (suppress ' the')",
        ))
        return [base, biased]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        if not responses:
            return self._inconclusive(
                getattr(self, "_skip_reason", "no probes sent")
            )
        base, biased = responses
        for r in (base, biased):
            if r.is_network_error:
                return self._inconclusive(r.error or "network error")
            if r.status_code != 200:
                return self._inconclusive(f"status {r.status_code}")
        base_count = _count_the(base.content or "")
        bias_count = _count_the(biased.content or "")
        ev = {"base_the_count": base_count, "bias_the_count": bias_count}

        if base_count < 5:
            return self._inconclusive(
                f"base run only has {base_count} 'the's -- not enough signal"
            )
        if bias_count <= 2:
            return self._pass(ev)
        ratio = bias_count / base_count
        if bias_count >= 5 and ratio > 0.5:
            # Only INCONCLUSIVE for native Anthropic format where logit_bias
            # genuinely doesn't exist. OpenAI-format proxies should support it.
            from ..models import ApiFormat
            if self.config.api_format == ApiFormat.ANTHROPIC:
                return self._inconclusive(
                    "logit_bias not in Anthropic API spec"
                )
            return self._fail(
                f"suppressed run still has {bias_count} 'the's "
                f"(base={base_count}, ratio={ratio:.0%}) "
                "-- logit_bias likely dropped", ev,
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
        base = mk("The library of the ancient world was the crown jewel of "
                  "the Mediterranean. The scholars who gathered at the site "
                  "preserved the texts of the classical era.")
        biased = mk("Alexandria housed a famous library. Scholars arrived to "
                    "study ancient texts there. Its collection spanned many "
                    "topics.")
        same = base
        return [
            ("PASS: bias honored (few 'the's after suppression)",
             [base, biased], "pass"),
            ("FAIL: bias dropped (same 'the' count)",
             [base, same], "fail"),
            ("INCONCLUSIVE: base has too few 'the's",
             [mk("hi"), mk("hi")], "inconclusive"),
            ("INCONCLUSIVE: network error",
             [base, ProbeResponse(status_code=0, error="T")], "inconclusive"),
        ]


if __name__ == "__main__":
    D70_LogitBiasHonor.self_test()
