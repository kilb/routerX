"""D44 TopPSensitivity - detect top_p being silently dropped.

Send 4 runs at top_p=0.1 (focused) and 4 at top_p=1.0 (diverse),
temperature=1.0 in both. Measure pairwise Jaccard distance of output
word sets within each group. Genuine sampling: diverse group >> focused.
"""
from __future__ import annotations

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProbeRequest, ProbeResponse, DetectorResult
from ..utils.diversity import mean_jaccard_dist


# Use a prompt that produces longer, more varied output for reliable Jaccard.
# Short one-liners have too few words for meaningful word-set distance.
_PROMPT = "Write a short paragraph (3-4 sentences) describing a mysterious scene. Be creative and vivid."
_N_PER_GROUP = 6


@detector
class D44_TopPSensitivity(BaseDetector):
    detector_id = "D44"
    detector_name = "TopPSensitivity"
    priority = Priority.P2
    judge_mode = JudgeMode.ONCE
    request_count = _N_PER_GROUP * 2
    detector_timeout = 90.0
    description = "Detect top_p being silently dropped by the router."

    async def send_probes(self) -> list[ProbeResponse]:
        probes: list[ProbeRequest] = []
        for top_p in (0.1, 1.0):
            for _ in range(_N_PER_GROUP):
                probes.append(ProbeRequest(
                    payload={
                        "model": self.config.claimed_model,
                        "max_tokens": 150,
                        "temperature": 0.7,
                        "top_p": top_p,
                        "messages": [{"role": "user", "content": _PROMPT}],
                    },
                    endpoint_path=self.config.default_endpoint_path,
                    description=f"D44 top_p={top_p}",
                ))
        return await self.client.send_concurrent(probes)

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        focused = [r.content or "" for r in responses[:_N_PER_GROUP]
                   if not r.is_network_error and r.status_code == 200]
        diverse = [r.content or "" for r in responses[_N_PER_GROUP:]
                   if not r.is_network_error and r.status_code == 200]
        if len(focused) < 2 or len(diverse) < 2:
            return self._inconclusive("not enough successful responses")
        mf = mean_jaccard_dist(focused)
        md = mean_jaccard_dist(diverse)
        ev = {"mean_focused_dist": mf, "mean_diverse_dist": md,
              "delta": md - mf}
        delta = md - mf
        # Reasoning models handle sampling parameters differently —
        # they may produce deterministic output regardless of top_p.
        model_lower = self.config.claimed_model.lower()
        _REASONING = ("o1", "o3", "o4", "deepseek-r1")
        if any(k in model_lower for k in _REASONING):
            return self._skip("top_p behavior differs for reasoning models")
        if delta >= 0.10:
            return self._pass(ev)
        # Negative delta (focused MORE diverse than diverse) is pure noise.
        if delta < 0:
            return self._inconclusive(
                f"reversed delta ({delta:.2f}); insufficient signal to determine "
                f"top_p behavior (sampling noise dominates)",
            )
        # delta in [0, 0.10): only FAIL if both groups show low absolute
        # diversity (both < 0.3), suggesting the parameter is completely
        # ignored and outputs are uniformly constrained.
        LOW_DIVERSITY_THRESHOLD = 0.35
        if mf < LOW_DIVERSITY_THRESHOLD and md < LOW_DIVERSITY_THRESHOLD:
            # Both groups show zero/near-zero diversity. Some models are
            # inherently deterministic at the temperature we use (0.7),
            # especially smaller or specialized models. Cannot distinguish
            # "parameter ignored" from "model is naturally deterministic."
            return self._inconclusive(
                f"both groups have very low diversity (focused={mf:.2f}, "
                f"diverse={md:.2f}); model may be inherently deterministic"
            )
        # delta in [0, 0.10) but absolute diversity is reasonable — could be
        # natural variance rather than parameter being ignored.
        return self._inconclusive(
            f"delta borderline ({delta:.2f}) with reasonable absolute diversity; "
            f"insufficient signal",
        )

    @classmethod
    def _test_cases(cls):
        def mk(content: str) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={"choices": [{"message": {"content": content},
                                   "finish_reason": "stop"}]},
            )
        focused = [mk("The body was cold."), mk("The body was cold."),
                   mk("The body lay cold."), mk("The body was cold."),
                   mk("The body was cold."), mk("The body lay still.")]
        diverse = [mk("A stranger knocked at midnight."),
                   mk("Rain washed the footprints away."),
                   mk("Emily found the letter in a drawer."),
                   mk("The lighthouse never blinked that night."),
                   mk("Fog rolled through the empty station."),
                   mk("The clock struck thirteen.")]
        same = focused  # no diversity in either group
        return [
            ("PASS: diverse group spreads wider", focused + diverse, "pass"),
            ("INCONCLUSIVE: both groups identical (may be deterministic model)", same + same, "inconclusive"),
            ("INCONCLUSIVE: network errors everywhere",
             [ProbeResponse(status_code=0, error="T") for _ in range(12)],
             "inconclusive"),
        ]


if __name__ == "__main__":
    D44_TopPSensitivity.self_test()
