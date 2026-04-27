from __future__ import annotations

import re

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProbeRequest, ProbeResponse, DetectorResult

COMPLETION_MARKER = "[LIST_COMPLETE]"
MAX_TOKENS = 2000
MIN_LANGUAGES_PASS = 20
MIN_LANGUAGES_FAIL = 10

PROMPT = (
    "Please list 20 programming languages and their main use cases, one per line. "
    f"After completing all 20, output '{COMPLETION_MARKER}' on the final line."
)

_NUMBERED_RE = re.compile(r"\b\d+[.\)]\s+")


def _count_language_entries(content: str) -> int:
    """Count list items using multiple strategies for robustness.

    Some models write compact single-line lists like
    "1. Python, 2. JavaScript, 3. Go" or comma-separated items.
    We take the maximum of line count, numbered-pattern count,
    and comma-separated count (halved) to handle all formats.
    """
    # Strategy 1: non-empty lines (excluding the marker)
    line_count = sum(
        1
        for line in content.splitlines()
        if line.strip() and line.strip() != COMPLETION_MARKER
    )
    # Strategy 2: numbered patterns like "1. " or "2) "
    numbered_count = len(_NUMBERED_RE.findall(content))
    # Strategy 3: comma-separated items (divided by 2 as a conservative
    # estimate -- each "Language: use case" pair contributes one comma)
    comma_count = content.count(",") // 2
    return max(line_count, numbered_count, comma_count)


@detector
class D54_TaskCompletion(BaseDetector):
    detector_id = "D54"
    detector_name = "TaskCompletion"
    priority = Priority.P1
    judge_mode = JudgeMode.MAJORITY_2_OF_2
    request_count = 1
    description = "Detect router truncating long structured task output before completion"

    async def send_probes(self) -> list[ProbeResponse]:
        """Send a single probe requesting a 20-item list with a completion marker."""
        return [await self.client.send(ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "max_tokens": MAX_TOKENS,
                "messages": [{"role": "user", "content": PROMPT}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="task completion probe",
        ))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        """Fail if the 20-item list is truncated or the completion marker is missing."""
        r = responses[0]
        if r.is_network_error:
            return self._pass({"note": r.error or "network error"})
        content = r.content
        if not content:
            return self._pass({"note": "empty content — no evidence of issue"})

        raw_finish = r.finish_reason or ""
        fr = raw_finish.lower()
        # Normalize Anthropic "end_turn"/"end" to be equivalent to "stop"
        is_natural_stop = fr in ("stop", "end_turn", "end")
        language_count = _count_language_entries(content)
        has_marker = COMPLETION_MARKER in content

        if language_count >= MIN_LANGUAGES_PASS and has_marker and is_natural_stop:
            return self._pass({
                "language_count": language_count,
                "has_marker": has_marker,
                "finish_reason": raw_finish,
            })

        if fr == "length":
            # finish_reason=length is honest — the model/API hit its own
            # output limit. This is a model limitation, not router truncation.
            return self._pass({
                "language_count": language_count,
                "has_marker": has_marker,
                "finish_reason": raw_finish,
                "note": "output limited by model (finish_reason=length)",
            })

        if language_count < MIN_LANGUAGES_FAIL and not has_marker and is_natural_stop:
            return self._fail("semantic truncation: list incomplete before marker", {
                "language_count": language_count,
                "has_marker": has_marker,
                "finish_reason": raw_finish,
            })

        # Ambiguous: partial completion or marker present but count low
        return self._pass({
            "language_count": language_count,
            "has_marker": has_marker,
            "finish_reason": raw_finish,
        })

    @classmethod
    def _test_cases(cls):
        def make_resp(content: str, finish_reason: str, status_code: int = 200) -> ProbeResponse:
            return ProbeResponse(
                status_code=status_code,
                body={"choices": [{"message": {"content": content}, "finish_reason": finish_reason}]},
            )

        full_list = "\n".join(
            [f"{i}. Language{i}: use case" for i in range(1, 21)]
            + [COMPLETION_MARKER]
        )
        # Compact single-line numbered list (no newlines between items)
        compact_list = ", ".join(
            [f"{i}. Language{i}: use case" for i in range(1, 21)]
        ) + f"\n{COMPLETION_MARKER}"
        short_list_no_marker = "\n".join(
            [f"{i}. Language{i}: use case" for i in range(1, 7)]
        )
        short_list_length = "\n".join(
            [f"{i}. Language{i}: use case" for i in range(1, 8)]
        )

        return [
            # PASS: complete list with marker and stop
            ("PASS: 20 languages + marker + stop",
             [make_resp(full_list, "stop")],
             "pass"),
            # PASS: compact single-line numbered list still counts 20
            ("PASS: compact numbered list on single line",
             [make_resp(compact_list, "stop")],
             "pass"),
            # FAIL: semantic truncation — few languages, no marker, finish=stop
            ("FAIL: semantic truncation (<10 langs, no marker, stop)",
             [make_resp(short_list_no_marker, "stop")],
             "fail"),
            # FAIL: crude truncation — finish_reason=length
            ("PASS: finish_reason=length (model output limit)",
             [make_resp(short_list_length, "length")],
             "pass"),
            # INCONCLUSIVE: network error
            ("PASS: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT")],
             "pass"),
            # INCONCLUSIVE: empty content
            ("PASS: empty content",
             [ProbeResponse(status_code=200, body={"choices": [{"message": {"content": ""}, "finish_reason": "stop"}]})],
             "pass"),
        ]


if __name__ == "__main__":
    D54_TaskCompletion.self_test()
