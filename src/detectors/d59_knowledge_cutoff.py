"""D59 KnowledgeCutoff -- verify model knows facts within its claimed cutoff.

Each frontier model has a documented training cutoff. A router substituting
an older open-source model will fail to recognize events/entities that the
claimed model definitely learned. We ask about 3 well-known, easily-verifiable
facts from the 'middle ground' (after old-OSS cutoffs, before claimed cutoff)
and require the model to identify at least 2.

We DO NOT test edge-of-cutoff facts (models often hedge on those).
"""
from __future__ import annotations

import re

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProbeRequest, ProbeResponse, DetectorResult


# Each probe: (question, list_of_acceptable_substrings_case_insensitive).
# Chosen so answers are definitive and widely known by 2024-era models but
# often unknown to pre-2023 OSS bases (Llama-2, Qwen-1).
#
# The third probe uses a regex for "x" so sentence-boundary occurrences
# like "rebranded to X." or "X is the new name" are caught.
_PROBES = [
    ("Who was announced as the 2023 Nobel Prize in Chemistry laureate for "
     "work on quantum dots? Name one of the three.",
     ["bawendi", "brus", "ekimov"]),
    ("What AI assistant did OpenAI launch publicly in November 2022?",
     ["chatgpt", "chat gpt"]),
    ("Twitter was rebranded to what single-letter name in 2023?",
     ["letter x", "rebranded to x", "called x", "named x", "known as x"]),
]

_X_WORD_RE = re.compile(r"\bx\b", re.IGNORECASE)


@detector
class D59_KnowledgeCutoff(BaseDetector):
    detector_id = "D59"
    detector_name = "KnowledgeCutoff"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = len(_PROBES)
    description = "Detect model substitution via post-2022 factual recall."

    async def send_probes(self) -> list[ProbeResponse]:
        probes = [ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "max_tokens": 120,
                "temperature": 0,
                "messages": [{"role": "user", "content": q}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="D59 cutoff probe",
        ) for q, _ in _PROBES]
        return await self.client.send_concurrent(probes)

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        hits = 0
        per_probe = []
        for (q, needles), r in zip(_PROBES, responses):
            if r.is_network_error or r.status_code != 200:
                per_probe.append({"q": q[:60], "ok": False, "reason": "network/status"})
                continue
            content = (r.content or "").lower()
            ok = any(n in content for n in needles)
            # Fallback regex for the Twitter/X probe — catches "X." at
            # sentence boundaries where substring needles miss.
            if not ok and "rebranded" in q.lower():
                ok = bool(_X_WORD_RE.search(content))
            if ok:
                hits += 1
            per_probe.append({"q": q[:60], "ok": ok, "excerpt": content[:150]})
        ev = {"hits": hits, "per_probe": per_probe}
        if hits >= 2:
            return self._pass(ev)
        return self._fail(
            f"only {hits}/{len(_PROBES)} well-known post-2022 facts recalled "
            "-- suggests pre-2023 open-source substitute", ev,
        )

    @classmethod
    def _test_cases(cls):
        def mk(content: str) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={"choices": [{"message": {"content": content},
                                   "finish_reason": "stop"}]},
            )
        good1 = mk("Moungi Bawendi was one of the 2023 Chemistry laureates.")
        good2 = mk("OpenAI launched ChatGPT in November 2022.")
        good3 = mk("Twitter rebranded to X in 2023.")
        bad = mk("I'm not sure about recent events.")
        return [
            ("PASS: all 3 recalled", [good1, good2, good3], "pass"),
            ("PASS: 2/3 recalled", [good1, good2, bad], "pass"),
            ("FAIL: 0/3 recalled", [bad, bad, bad], "fail"),
            ("FAIL: 1/3 recalled", [good1, bad, bad], "fail"),
            ("INCONCLUSIVE is n/a -- network errors count as misses",
             [ProbeResponse(status_code=0, error="TIMEOUT"), good2, good3], "pass"),
        ]


if __name__ == "__main__":
    D59_KnowledgeCutoff.self_test()
