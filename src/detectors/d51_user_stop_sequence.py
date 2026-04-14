"""D51 UserStopSequence — verify user-supplied stop sequences truncate output.

Ask the model to output a short ordered list ending with the literal token
DONE followed by additional text. With stop=['DONE'] a compliant API must
truncate at DONE (and omit it from content). Fraud: router drops stop param;
output contains DONE or continues past it.
"""
from __future__ import annotations

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProbeRequest, ProbeResponse, DetectorResult

_STOP = "DONE"


@detector
class D51_UserStopSequence(BaseDetector):
    detector_id = "D51"
    detector_name = "UserStopSequence"
    priority = Priority.P2
    judge_mode = JudgeMode.ONCE
    request_count = 1
    description = "Detect user-supplied stop sequence being silently dropped."

    async def send_probes(self) -> list[ProbeResponse]:
        prompt = (
            "Count slowly: output exactly the lines 'ONE', 'TWO', 'THREE', "
            f"then the token {_STOP}, then 'FOUR', 'FIVE'. One per line."
        )
        return [await self.client.send(ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "max_tokens": 80,
                "temperature": 0,
                "stop": [_STOP],
                "messages": [{"role": "user", "content": prompt}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="D51 stop sequence probe",
        ))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error or "network error")
        if r.status_code != 200:
            return self._inconclusive(f"status {r.status_code}")
        content = r.content or ""
        finish = (r.finish_reason or "").lower()
        ev = {"content": content, "finish_reason": finish}
        has_stop = _STOP in content
        has_after = any(tok in content for tok in ("FOUR", "FIVE"))
        if not has_stop and not has_after:
            return self._pass(ev)
        return self._fail(
            f"stop sequence not honored: stop_token_echoed={has_stop}, "
            f"after_tokens_present={has_after}", ev,
        )

    @classmethod
    def _test_cases(cls):
        def mk(content: str, finish: str = "stop") -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={"choices": [{"message": {"content": content},
                                   "finish_reason": finish}]},
            )
        return [
            ("PASS: truncated before DONE",
             [mk("ONE\nTWO\nTHREE\n", "stop")], "pass"),
            ("FAIL: DONE echoed", [mk("ONE\nTWO\nTHREE\nDONE\n")], "fail"),
            ("FAIL: continued past DONE",
             [mk("ONE\nTWO\nTHREE\nDONE\nFOUR\nFIVE")], "fail"),
            ("INCONCLUSIVE: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT")], "inconclusive"),
        ]


if __name__ == "__main__":
    D51_UserStopSequence.self_test()
