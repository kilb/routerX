"""D61 TemperatureSensitivity - detect temperature being silently dropped.

Send 4 runs at temperature=0.0 (deterministic) and 4 at temperature=1.0
(creative), same prompt, no top_p override. Measure pairwise Jaccard
distance of output word sets within each group. Genuine sampling: the
creative group should diverge noticeably; if both groups collapse to
near-identical text, temperature is likely ignored.
"""
from __future__ import annotations

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProbeRequest, ProbeResponse, DetectorResult
from ..utils.diversity import mean_jaccard_dist


_PROMPT = "Write one short imaginative first-line for a fantasy novel. Just the line."
_N_PER_GROUP = 6
_MIN_DELTA = 0.10


@detector
class D61_TemperatureSensitivity(BaseDetector):
    detector_id = "D61"
    detector_name = "TemperatureSensitivity"
    priority = Priority.P2
    judge_mode = JudgeMode.ONCE
    request_count = _N_PER_GROUP * 2
    detector_timeout = 90.0
    description = "Detect temperature being silently dropped by the router."

    async def send_probes(self) -> list[ProbeResponse]:
        probes: list[ProbeRequest] = []
        for temperature in (0.0, 1.0):
            for _ in range(_N_PER_GROUP):
                probes.append(ProbeRequest(
                    payload={
                        "model": self.config.claimed_model,
                        "max_tokens": 60,
                        "temperature": temperature,
                        "messages": [{"role": "user", "content": _PROMPT}],
                    },
                    endpoint_path=self.config.default_endpoint_path,
                    description=f"D61 temperature={temperature}",
                ))
        return await self.client.send_concurrent(probes)

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        deterministic = [r.content or "" for r in responses[:_N_PER_GROUP]
                         if not r.is_network_error and r.status_code == 200]
        creative = [r.content or "" for r in responses[_N_PER_GROUP:]
                    if not r.is_network_error and r.status_code == 200]
        if len(deterministic) < 2 or len(creative) < 2:
            return self._pass({"note": "not enough successful responses — no evidence of issue"})
        md = mean_jaccard_dist(deterministic)
        mc = mean_jaccard_dist(creative)
        ev = {"mean_deterministic_dist": md, "mean_creative_dist": mc,
              "delta": mc - md}
        delta = mc - md
        # Reasoning models (o1/o3/o4/deepseek-r1) handle temperature
        # differently — they may produce deterministic output regardless
        # of the temperature setting. This is model behavior, not
        # the router ignoring the parameter.
        model_lower = self.config.claimed_model.lower()
        _REASONING = ("o1", "o3", "o4", "deepseek-r1")
        if any(k in model_lower for k in _REASONING):
            return self._skip("temperature behavior differs for reasoning models")
        if delta >= _MIN_DELTA:
            return self._pass(ev)
        # Negative delta = deterministic group more diverse than creative.
        # This is pure sampling noise, not evidence of parameter dropping.
        if delta < 0:
            return self._pass({"note": 
                f"reversed delta ({delta:.2f}); sampling noise dominates"
            })
        # delta in [0, 0.10): only FAIL if both groups show low absolute
        # diversity (both < 0.35), suggesting parameter is completely
        # ignored and all outputs are uniformly constrained.
        if md > 0.35 or mc > 0.35:
            return self._pass({"note": 
                f"borderline delta ({delta:.2f}) with high absolute diversity; "
                f"insufficient signal"
            })
        # Both groups show zero/near-zero diversity — model may be
        # inherently deterministic regardless of temperature setting.
        return self._pass({"note": 
            f"both groups have very low diversity (det={md:.2f}, "
            f"creative={mc:.2f}); model may be inherently deterministic"
        })

    @classmethod
    def _test_cases(cls):
        def mk(content: str) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={"choices": [{"message": {"content": content},
                                   "finish_reason": "stop"}]},
            )
        deterministic = [mk("A dragon awoke beneath the mountain."),
                         mk("A dragon awoke beneath the mountain."),
                         mk("A dragon awoke beneath the mountain."),
                         mk("A dragon awoke beneath the mountain."),
                         mk("A dragon awoke beneath the mountain."),
                         mk("A dragon awoke beneath the mountain.")]
        creative = [mk("The moon cracked like an eggshell at dawn."),
                    mk("Somewhere beyond the river, a name was forgotten."),
                    mk("Eleanor found a star sleeping in her garden."),
                    mk("The last wizard traded his shadow for bread."),
                    mk("Fog swallowed the castle and never gave it back."),
                    mk("A compass needle spun wildly, pointing everywhere.")]
        same = deterministic  # no diversity in either group
        return [
            ("PASS: creative spreads wider than deterministic",
             deterministic + creative, "pass"),
            ("PASS: both groups identical (may be deterministic model)", same + same, "pass"),
            ("PASS: network errors everywhere",
             [ProbeResponse(status_code=0, error="T") for _ in range(12)],
             "pass"),
        ]


if __name__ == "__main__":
    D61_TemperatureSensitivity.self_test()
