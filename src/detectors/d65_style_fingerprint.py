"""D65 StyleFingerprint -- detect family substitution via writing-style stats.

Frontier model families leave measurable style signatures: average sentence
length, em-dash density, bullet-list preference, opening-phrase patterns,
passive-voice rate. Substituted smaller/OSS models diverge statistically.

HEURISTIC thresholds; pure-style mismatch alone is not conclusive -- pair
with D41/D4a. MAJORITY_2_OF_2 reduces single-sample variance.
"""
from __future__ import annotations

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProbeRequest, ProbeResponse, DetectorResult
from ..utils.style_stats import feature_vector, normalized_distance, infer_family


_PROMPTS = [
    "Who wrote Pride and Prejudice?",
    "Describe a foggy morning in a coastal town in 3-4 sentences.",
    "Explain how a TCP three-way handshake works in plain language.",
]

_MAX_DISTANCE = 3.0


@detector
class D65_StyleFingerprint(BaseDetector):
    detector_id = "D65"
    detector_name = "StyleFingerprint"
    priority = Priority.P2
    judge_mode = JudgeMode.MAJORITY_2_OF_2
    request_count = len(_PROMPTS)
    detector_timeout = 60.0
    description = (
        "Detect model-family substitution via writing-style feature distance "
        "from claimed-family centroid."
    )

    async def send_probes(self) -> list[ProbeResponse]:
        out = []
        for p in _PROMPTS:
            out.append(await self.client.send(ProbeRequest(
                payload={
                    "model": self.config.claimed_model,
                    "max_tokens": 200,
                    "temperature": 0.3,
                    "messages": [{"role": "user", "content": p}],
                },
                endpoint_path=self.config.default_endpoint_path,
                description="D65 style probe",
            )))
        return out

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        family = infer_family(self.config.claimed_model)
        if family is None:
            return self._inconclusive(
                f"unknown family for model {self.config.claimed_model!r}"
            )
        texts = [r.content or "" for r in responses
                 if not r.is_network_error and r.status_code == 200]
        if len(texts) < 2:
            return self._inconclusive("not enough valid responses")
        vectors = [feature_vector(t) for t in texts]
        mean_fv = {k: sum(v[k] for v in vectors) / len(vectors)
                   for k in vectors[0]}
        dist = normalized_distance(mean_fv, family)
        ev = {"family": family, "mean_features": mean_fv, "distance": dist}
        if dist is None:
            return self._inconclusive(f"no centroid for family {family!r}")
        if dist > _MAX_DISTANCE:
            return self._fail(
                f"style distance {dist:.2f} from {family} centroid exceeds "
                f"threshold {_MAX_DISTANCE}", ev,
            )
        return self._pass(ev)

    @classmethod
    def _test_cases(cls):
        def mk(content: str) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={"choices": [{"message": {"content": content},
                                   "finish_reason": "stop"}]},
            )
        # Text matching typical GPT centroid (our self_test uses gpt-4o).
        on_family = (
            "Sure! Here's a clear explanation. TCP uses three packets to "
            "establish a connection. The client sends a SYN \u2014 the server "
            "responds with SYN-ACK. Finally, the client sends ACK.\n"
            "- Step one: SYN.\n- Step two: SYN-ACK.\n- Step three: ACK."
        )
        off_family = "Yes. " * 60
        good = [mk(on_family)] * 3
        bad = [mk(off_family)] * 3
        return [
            ("PASS: on-family style", good, "pass"),
            ("FAIL: very off-family style", bad, "fail"),
            ("INCONCLUSIVE: network errors",
             [ProbeResponse(status_code=0, error="T") for _ in range(3)],
             "inconclusive"),
        ]


if __name__ == "__main__":
    D65_StyleFingerprint.self_test()
