from __future__ import annotations

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProbeRequest, ProbeResponse, DetectorResult

COMPLETION_MARKER = "[LIST_COMPLETE]"
MAX_TOKENS = 2000
MIN_LANGUAGES_PASS = 20
MIN_LANGUAGES_FAIL = 15

PROMPT = (
    "Please list 20 programming languages and their main use cases, one per line. "
    f"After completing all 20, output '{COMPLETION_MARKER}' on the final line."
)


def _count_language_entries(content: str) -> int:
    """Count non-empty lines that are not the completion marker."""
    return sum(
        1
        for line in content.splitlines()
        if line.strip() and line.strip() != COMPLETION_MARKER
    )


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
            return self._inconclusive(r.error or "network error")
        content = r.content
        if not content:
            return self._inconclusive("empty content")

        finish_reason = r.finish_reason or ""
        language_count = _count_language_entries(content)
        has_marker = COMPLETION_MARKER in content

        if language_count >= MIN_LANGUAGES_PASS and has_marker and finish_reason == "stop":
            return self._pass({
                "language_count": language_count,
                "has_marker": has_marker,
                "finish_reason": finish_reason,
            })

        if finish_reason == "length":
            return self._fail("crude truncation: finish_reason=length", {
                "language_count": language_count,
                "has_marker": has_marker,
                "finish_reason": finish_reason,
            })

        if language_count < MIN_LANGUAGES_FAIL and not has_marker and finish_reason == "stop":
            return self._fail("semantic truncation: list incomplete before marker", {
                "language_count": language_count,
                "has_marker": has_marker,
                "finish_reason": finish_reason,
            })

        # Ambiguous: partial completion or marker present but count low
        return self._pass({
            "language_count": language_count,
            "has_marker": has_marker,
            "finish_reason": finish_reason,
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
        short_list_no_marker = "\n".join(
            [f"{i}. Language{i}: use case" for i in range(1, 11)]
        )
        short_list_length = "\n".join(
            [f"{i}. Language{i}: use case" for i in range(1, 8)]
        )

        return [
            # PASS: complete list with marker and stop
            ("PASS: 20 languages + marker + stop",
             [make_resp(full_list, "stop")],
             "pass"),
            # FAIL: semantic truncation — few languages, no marker, finish=stop
            ("FAIL: semantic truncation (<15 langs, no marker, stop)",
             [make_resp(short_list_no_marker, "stop")],
             "fail"),
            # FAIL: crude truncation — finish_reason=length
            ("FAIL: crude truncation (finish_reason=length)",
             [make_resp(short_list_length, "length")],
             "fail"),
            # INCONCLUSIVE: network error
            ("INCONCLUSIVE: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT")],
             "inconclusive"),
            # INCONCLUSIVE: empty content
            ("INCONCLUSIVE: empty content",
             [ProbeResponse(status_code=200, body={"choices": [{"message": {"content": ""}, "finish_reason": "stop"}]})],
             "inconclusive"),
        ]


if __name__ == "__main__":
    D54_TaskCompletion.self_test()
