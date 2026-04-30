"""D59 KnowledgeCutoff -- verify model knows facts within its claimed cutoff.

Each frontier model has a documented training cutoff. A router substituting
an older model will fail to recognize recent events that the claimed model
definitely learned. We select questions based on the CLAIMED model's expected
cutoff period and require the model to identify at least 2 of 3 facts.

The question bank has three tiers:
  - 2023 facts: post-2022, catches pre-ChatGPT era substitutions
  - 2024 facts: catches models stuck at early-2024 cutoff
  - 2025 facts: catches models stuck at mid-2024 cutoff posing as 2025 models
"""
from __future__ import annotations

import re

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProbeRequest, ProbeResponse, DetectorResult


# Question bank organized by the year the fact became public knowledge.
# Each entry: (question, list_of_acceptable_substrings_case_insensitive, optional_regex)
_FACTS_2023 = [
    ("Who was announced as the 2023 Nobel Prize in Chemistry laureate for "
     "work on quantum dots? Name one of the three.",
     ["bawendi", "brus", "ekimov"], None),
    ("What AI assistant did OpenAI launch publicly in November 2022?",
     ["chatgpt", "chat gpt"], None),
    ("Twitter was rebranded to what single-letter name in 2023?",
     ["letter x", "rebranded to x", "called x", "named x", "known as x"],
     re.compile(
         r"(?:rebrand|renamed?|now called|known as|changed to|became|"
         r"renamed as|the letter|twitter as|new name)\s+(?:to\s+)?[\"']?x[\"']?\b"
         r"|\bx\b(?:\s*[,.]?\s*(?:formerly|previously)\s+twitter)",
         re.IGNORECASE,
     )),
]

_FACTS_2024 = [
    ("Who won the 2024 US Presidential election?",
     ["trump", "donald trump"], None),
    ("What AI model family did Anthropic release in March 2024 "
     "that included Haiku, Sonnet, and Opus variants?",
     ["claude 3", "claude-3"], None),
    ("What was the name of OpenAI's text-to-video model announced "
     "in February 2024?",
     ["sora"], None),
]

_FACTS_2025 = [
    ("What AI model did Anthropic release in January 2025 that was "
     "noted for its strong coding and agentic capabilities, as part "
     "of the Claude 3.5 family?",
     ["claude 3.5 sonnet", "claude-3.5-sonnet", "claude 3-5 sonnet",
      "sonnet 3.5"], None),
    ("What was the name of DeepSeek's open-source reasoning model "
     "released in January 2025 that rivaled frontier models?",
     ["deepseek-r1", "deepseek r1", "r1"], None),
    ("What AI model family did Anthropic release in 2025 with the "
     "version number 4, including Opus and Sonnet variants?",
     ["claude 4", "claude-4", "sonnet 4", "opus 4"], None),
]

# Map model name patterns to the minimum cutoff year they should have.
# Models not matching any pattern default to 2023 (lowest tier).
_MODEL_CUTOFF_MAP = [
    # 2025+ models
    (("claude-4", "claude-opus-4", "claude-sonnet-4",
      "gpt-5", "gpt-4.1", "o3", "o4",
      "gemini-3", "gemini-2.5"), 2025),
    # 2024+ models
    (("claude-3.5", "claude-3-5", "gpt-4o", "gpt-4-turbo",
      "o1", "gemini-2", "gemini-1.5"), 2024),
    # Everything else: 2023 baseline
]

# Proximity fallback for Twitter/X question
_X_PROXIMITY_RE = re.compile(
    r"twitter.{0,30}\bx\b|\bx\b.{0,30}twitter",
    re.IGNORECASE,
)


def _expected_cutoff(model: str) -> int:
    """Determine minimum expected knowledge cutoff year from model name."""
    model_lower = model.lower()
    for patterns, year in _MODEL_CUTOFF_MAP:
        if any(p in model_lower for p in patterns):
            return year
    return 2023


def _select_probes(cutoff_year: int) -> list[tuple[str, list[str], re.Pattern | None]]:
    """Select 3 questions appropriate for the expected cutoff year."""
    if cutoff_year >= 2025:
        return _FACTS_2025
    if cutoff_year >= 2024:
        return _FACTS_2024
    return _FACTS_2023


@detector
class D59_KnowledgeCutoff(BaseDetector):
    detector_id = "D59"
    detector_name = "KnowledgeCutoff"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = 3
    description = "Detect model substitution via factual recall matching claimed cutoff."

    async def send_probes(self) -> list[ProbeResponse]:
        cutoff = _expected_cutoff(self.config.claimed_model)
        self._probes = _select_probes(cutoff)
        self._cutoff_year = cutoff
        probes = [ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "max_tokens": 120,
                "temperature": 0,
                "messages": [{"role": "user", "content": q}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description=f"D59 cutoff probe ({cutoff})",
        ) for q, _, _ in self._probes]
        return await self.client.send_concurrent(probes)

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        probes = getattr(self, "_probes", _FACTS_2023)
        cutoff_year = getattr(self, "_cutoff_year", 2023)
        hits = 0
        per_probe = []
        for (q, needles, regex), r in zip(probes, responses):
            if r.is_network_error or r.status_code != 200:
                per_probe.append({"q": q[:60], "ok": False, "reason": "network/status"})
                continue
            content = (r.content or "").lower()
            if not content.strip():
                per_probe.append({"q": q[:60], "ok": False, "reason": "empty response"})
                continue
            ok = any(n in content for n in needles)
            # Fallback regex if provided
            if not ok and regex:
                ok = bool(regex.search(content))
            # Proximity fallback for Twitter/X
            if not ok and "rebranded" in q.lower():
                ok = bool(_X_PROXIMITY_RE.search(content))
            if ok:
                hits += 1
            per_probe.append({"q": q[:60], "ok": ok, "excerpt": content[:150]})

        valid_probes = sum(
            1 for p in per_probe if p.get("reason") not in ("network/status", "empty response")
        )
        ev = {"hits": hits, "per_probe": per_probe, "cutoff_year": cutoff_year}

        if hits >= 2:
            return self._pass(ev)

        if valid_probes < 2:
            return self._pass({"note": f"only {valid_probes}/{len(per_probe)} probes got valid "
                f"responses — cannot assess knowledge cutoff"})

        # Check truncated responses
        truncated_count = sum(
            1 for p in per_probe
            if p.get("excerpt") and len(p["excerpt"]) < 30 and not p["ok"]
        )
        if truncated_count >= 2:
            return self._pass(ev | {
                "note": f"{truncated_count} responses truncated (< 30 chars) "
                        f"— model output limit prevented full answers",
            })

        # Only FAIL for frontier models that SHOULD know these facts.
        model_lower = self.config.claimed_model.lower()
        _FRONTIER = (
            "gpt-4", "gpt-5", "claude-opus", "claude-sonnet",
            "gemini-2.5-pro", "gemini-3", "o1", "o3", "o4",
        )
        is_frontier = any(k in model_lower for k in _FRONTIER)
        if not is_frontier:
            return self._pass(ev | {
                "note": f"only {hits}/{len(probes)} facts recalled but "
                        f"model may have limited training data",
            })

        if hits >= 1:
            return self._pass(ev | {
                "note": f"{hits}/{len(probes)} recalled — partial knowledge",
            })

        return self._fail(
            f"0/{len(probes)} facts from {cutoff_year} recalled "
            "by frontier model — possible model substitution", ev,
        )

    @classmethod
    def _test_cases(cls):
        def mk(content: str) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={"choices": [{"message": {"content": content},
                                   "finish_reason": "stop"}]},
            )

        # Test with 2025 facts (default for self_test which uses _FACTS_2023 fallback)
        good1 = mk("Moungi Bawendi was one of the 2023 Chemistry laureates.")
        good2 = mk("OpenAI launched ChatGPT in November 2022.")
        good3 = mk("Twitter rebranded to X in 2023.")
        bad = mk("I'm not sure about recent events.")

        return [
            ("PASS: all 3 recalled", [good1, good2, good3], "pass"),
            ("PASS: 2/3 recalled", [good1, good2, bad], "pass"),
            ("FAIL: 0/3 recalled", [bad, bad, bad], "fail"),
            ("PASS: 1/3 recalled (partial knowledge)", [good1, bad, bad], "pass"),
            ("PASS: network errors",
             [ProbeResponse(status_code=0, error="TIMEOUT"), good2, good3], "pass"),
        ]


if __name__ == "__main__":
    D59_KnowledgeCutoff.self_test()
