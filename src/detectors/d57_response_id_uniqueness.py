"""D57 ResponseIDUniqueness — each response must have a unique id.

A legitimate provider assigns a unique request id per call (`id` in OpenAI
responses, `id` in Anthropic). Some scam routers return a hardcoded id or
echo the model name. Send 3 identical requests; detect duplicate ids.
"""
from __future__ import annotations

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProbeRequest, ProbeResponse, DetectorResult

_N = 5


@detector
class D57_ResponseIDUniqueness(BaseDetector):
    detector_id = "D57"
    detector_name = "ResponseIDUniqueness"
    priority = Priority.P2
    judge_mode = JudgeMode.ONCE
    request_count = _N
    description = "Detect duplicate response ids -- marker of template/fake responses."

    async def send_probes(self) -> list[ProbeResponse]:
        probes = [ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "max_tokens": 5,
                "temperature": 0,
                "messages": [{"role": "user", "content": "Reply with just 'ok'."}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description=f"D57 id probe {i}",
        ) for i in range(_N)]
        return await self.client.send_concurrent(probes)

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        ids = []
        for r in responses:
            if r.is_network_error or r.status_code != 200 or not r.body:
                continue
            rid = r.body.get("id") or r.body.get("response_id")
            if rid:
                ids.append(rid)
        ev = {"ids": ids}
        if len(ids) < 2:
            return self._pass({"note": "not enough responses with ids — no evidence of issue"})
        if len(set(ids)) == len(ids):
            return self._pass(ev)
        return self._fail(
            f"duplicate response ids: {ids} -- router likely returns templated response", ev,
        )

    @classmethod
    def _test_cases(cls):
        def mk(rid: str) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={"id": rid,
                      "choices": [{"message": {"content": "ok"},
                                   "finish_reason": "stop"}]},
            )
        return [
            ("PASS: unique ids",
             [mk(f"chatcmpl-a{i}") for i in range(_N)],
             "pass"),
            ("FAIL: all ids identical",
             [mk("chatcmpl-x") for _ in range(_N)],
             "fail"),
            ("PASS: no ids at all",
             [ProbeResponse(status_code=200,
                            body={"choices": [{"message": {"content": "ok"}}]})
              for _ in range(_N)],
             "pass"),
            ("PASS: all network errors",
             [ProbeResponse(status_code=0, error="T") for _ in range(_N)],
             "pass"),
        ]


if __name__ == "__main__":
    D57_ResponseIDUniqueness.self_test()
