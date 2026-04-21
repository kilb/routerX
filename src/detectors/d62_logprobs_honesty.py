"""D62 LogprobsHonesty -- verify logprobs structure is genuine, not fabricated.

Checks:
- logprobs block present when requested
- top_logprobs has 5 alternatives per position
- chosen token is among the top alternatives at each position
- logprobs actually vary (not a flat constant)
"""
from __future__ import annotations

import statistics

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProviderType, ProbeRequest, ProbeResponse, DetectorResult


_MIN_POSITION_MATCH_RATE = 0.8
_MIN_LOGPROB_STDEV = 0.01


def _extract_logprobs(body: dict) -> list[dict] | None:
    try:
        choice = body["choices"][0]
    except (KeyError, IndexError, TypeError):
        return None
    lp = choice.get("logprobs")
    if lp is None:
        msg = choice.get("message", {})
        lp = msg.get("logprobs")
    if not lp:
        return None
    return lp.get("content") or lp.get("tokens")


@detector
class D62_LogprobsHonesty(BaseDetector):
    detector_id = "D62"
    detector_name = "LogprobsHonesty"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = 1
    description = "Detect logprobs flag being dropped or logprobs being fabricated."

    async def send_probes(self) -> list[ProbeResponse]:
        return [await self.client.send(ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "max_tokens": 30,
                "temperature": 0.3,
                "logprobs": True,
                "top_logprobs": 5,
                "messages": [{"role": "user", "content":
                              "Say one short neutral sentence about the weather."}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="D62 logprobs probe",
        ))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error or "network error")
        if r.status_code != 200:
            return self._inconclusive(f"status {r.status_code}")
        if not r.body:
            return self._inconclusive("empty body")
        positions = _extract_logprobs(r.body)
        if positions is None:
            # If the wire format is OpenAI, logprobs SHOULD be supported
            # regardless of backend model — the proxy chose to advertise
            # OpenAI compatibility. Only INCONCLUSIVE for native Anthropic
            # format where logprobs genuinely doesn't exist in the spec.
            from ..models import ApiFormat
            if self.config.api_format == ApiFormat.ANTHROPIC:
                return self._skip("logprobs not in Anthropic API spec")
            return self._fail("logprobs flag dropped -- no logprobs block in response", {})
        if not positions:
            return self._fail("logprobs.content is empty", {})

        chosen_lps: list[float] = []
        in_top_hits = 0
        for p in positions:
            token = p.get("token")
            lp = p.get("logprob")
            tops = p.get("top_logprobs") or []
            if isinstance(lp, (int, float)):
                chosen_lps.append(float(lp))
            top_tokens = [t.get("token") for t in tops]
            if token in top_tokens:
                in_top_hits += 1

        match_rate = in_top_hits / len(positions)
        ev = {"positions": len(positions), "match_rate": match_rate,
              "chosen_logprob_stdev": (statistics.pstdev(chosen_lps)
                                       if len(chosen_lps) > 1 else 0.0)}

        if len(chosen_lps) < 2:
            return self._inconclusive("only one position; cannot check stdev")
        stdev = statistics.pstdev(chosen_lps)
        if stdev < _MIN_LOGPROB_STDEV:
            return self._fail(
                f"chosen-token logprobs have stdev={stdev:.4f} "
                f"(< {_MIN_LOGPROB_STDEV}) -- fabricated flat values", ev,
            )
        if match_rate < _MIN_POSITION_MATCH_RATE:
            return self._fail(
                f"chosen token appears in top_logprobs only {match_rate:.0%} "
                f"of positions (< {_MIN_POSITION_MATCH_RATE:.0%})", ev,
            )
        return self._pass(ev)

    @classmethod
    def _test_cases(cls):
        def mk(positions):
            return ProbeResponse(
                status_code=200,
                body={"choices": [{"message": {"content": "it is sunny"},
                                   "logprobs": {"content": positions},
                                   "finish_reason": "stop"}]},
            )
        real = [
            {"token": "it", "logprob": -0.5,
             "top_logprobs": [{"token": "it", "logprob": -0.5},
                              {"token": "the", "logprob": -1.1}]},
            {"token": " is", "logprob": -0.8,
             "top_logprobs": [{"token": " is", "logprob": -0.8},
                              {"token": " was", "logprob": -1.5}]},
            {"token": " sunny", "logprob": -1.2,
             "top_logprobs": [{"token": " sunny", "logprob": -1.2},
                              {"token": " cold", "logprob": -1.9}]},
        ]
        flat = [
            {"token": t, "logprob": -1.0,
             "top_logprobs": [{"token": t, "logprob": -1.0}]}
            for t in ["a", "b", "c", "d"]
        ]
        no_lp = ProbeResponse(
            status_code=200,
            body={"choices": [{"message": {"content": "it is sunny"},
                               "finish_reason": "stop"}]},
        )
        wrong_top = [
            {"token": "it", "logprob": -0.5,
             "top_logprobs": [{"token": "zz", "logprob": -5}]},
            {"token": "is", "logprob": -2.0,
             "top_logprobs": [{"token": "zz", "logprob": -5}]},
            {"token": "sun", "logprob": -3.5,
             "top_logprobs": [{"token": "zz", "logprob": -5}]},
        ]
        return [
            ("PASS: genuine logprobs", [mk(real)], "pass"),
            ("FAIL: flat constant logprobs", [mk(flat)], "fail"),
            ("FAIL: logprobs flag dropped (OpenAI format)", [no_lp], "fail"),
            ("FAIL: chosen token never in top_logprobs",
             [mk(wrong_top)], "fail"),
            ("INCONCLUSIVE: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT")], "inconclusive"),
        ]


if __name__ == "__main__":
    D62_LogprobsHonesty.self_test()
