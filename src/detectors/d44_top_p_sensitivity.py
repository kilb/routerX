"""D44 TopPSensitivity - detect top_p being silently dropped.

Send 4 runs at top_p=0.1 (focused) and 4 at top_p=1.0 (diverse),
temperature=1.0 in both. Measure pairwise Jaccard distance of output
word sets within each group. Genuine sampling: diverse group >> focused.
"""
from __future__ import annotations

from itertools import combinations
import re

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProbeRequest, ProbeResponse, DetectorResult


_PROMPT = "Write one short, creative opening line for a mystery novel. Just the line, nothing else."
_N_PER_GROUP = 4
_WORD_RE = re.compile(r"[a-z']+")


def _word_set(text: str) -> set[str]:
    return set(_WORD_RE.findall(text.lower()))


def _mean_jaccard_dist(texts: list[str]) -> float:
    sets = [_word_set(t) for t in texts if t]
    if len(sets) < 2:
        return 0.0
    dists = []
    for a, b in combinations(sets, 2):
        union = a | b
        if not union:
            continue
        dists.append(1 - len(a & b) / len(union))
    return sum(dists) / len(dists) if dists else 0.0


@detector
class D44_TopPSensitivity(BaseDetector):
    detector_id = "D44"
    detector_name = "TopPSensitivity"
    priority = Priority.P2
    judge_mode = JudgeMode.MAJORITY_2_OF_2
    request_count = _N_PER_GROUP * 2
    detector_timeout = 90.0
    description = "Detect top_p being silently dropped by the router."

    async def send_probes(self) -> list[ProbeResponse]:
        out: list[ProbeResponse] = []
        for top_p in (0.1, 1.0):
            for _ in range(_N_PER_GROUP):
                out.append(await self.client.send(ProbeRequest(
                    payload={
                        "model": self.config.claimed_model,
                        "max_tokens": 60,
                        "temperature": 1.0,
                        "top_p": top_p,
                        "messages": [{"role": "user", "content": _PROMPT}],
                    },
                    endpoint_path=self.config.default_endpoint_path,
                    description=f"D44 top_p={top_p}",
                )))
        return out

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        focused = [r.content or "" for r in responses[:_N_PER_GROUP]
                   if not r.is_network_error and r.status_code == 200]
        diverse = [r.content or "" for r in responses[_N_PER_GROUP:]
                   if not r.is_network_error and r.status_code == 200]
        if len(focused) < 2 or len(diverse) < 2:
            return self._inconclusive("not enough successful responses")
        mf = _mean_jaccard_dist(focused)
        md = _mean_jaccard_dist(diverse)
        ev = {"mean_focused_dist": mf, "mean_diverse_dist": md,
              "delta": md - mf}
        if md - mf >= 0.05:
            return self._pass(ev)
        return self._fail(
            f"diverse-group diversity ({md:.2f}) not meaningfully > "
            f"focused-group ({mf:.2f}); top_p likely ignored", ev,
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
                   mk("The body lay cold."), mk("The body was cold.")]
        diverse = [mk("A stranger knocked at midnight."),
                   mk("Rain washed the footprints away."),
                   mk("Emily found the letter in a drawer."),
                   mk("The lighthouse never blinked that night.")]
        same = focused  # no diversity in either group
        return [
            ("PASS: diverse group spreads wider", focused + diverse, "pass"),
            ("FAIL: both groups identical", same + same, "fail"),
            ("INCONCLUSIVE: network errors everywhere",
             [ProbeResponse(status_code=0, error="T") for _ in range(8)],
             "inconclusive"),
        ]


if __name__ == "__main__":
    D44_TopPSensitivity.self_test()
