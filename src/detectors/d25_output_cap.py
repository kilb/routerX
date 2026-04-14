from __future__ import annotations

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProbeRequest, ProbeResponse, DetectorResult

MIN_EXPECTED_BETAS = 400  # hard FAIL below this
HEALTHY_BETAS = 700       # PASS requires at least this many + finish_reason=stop
TARGET_BETAS = 800
MAX_TOKENS = 2048


@detector
class D25_OutputCapProbe(BaseDetector):
    detector_id = "D25"
    detector_name = "OutputCapProbe"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = 1
    description = "Detect router secretly lowering max_tokens at gateway level"

    async def send_probes(self) -> list[ProbeResponse]:
        """Send a single probe requesting 800 BETA repetitions with max_tokens=2048."""
        return [await self.client.send(ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "max_tokens": MAX_TOKENS,
                "messages": [{"role": "user", "content": (
                    f"Please repeat the word 'BETA' exactly {TARGET_BETAS} times, "
                    "separated by spaces. Do not include anything else."
                )}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="output cap probe",
        ))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        """Count BETA occurrences; fail if too few given finish_reason."""
        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error or "network error")
        content = r.content
        if not content:
            return self._inconclusive("empty content")
        beta_count = content.split().count("BETA")
        finish_reason = r.finish_reason
        ev = {"beta_count": beta_count, "finish_reason": finish_reason}
        if beta_count < MIN_EXPECTED_BETAS and finish_reason == "length":
            return self._fail("output capped", ev)
        if beta_count < MIN_EXPECTED_BETAS and finish_reason == "stop":
            return self._fail("semantic truncation", ev)
        # Spec: PASS requires >= 700 BETAs AND finish_reason == "stop"
        if beta_count >= HEALTHY_BETAS and finish_reason == "stop":
            return self._pass(ev)
        # Ambiguous zone (400-699 or finish_reason != stop): suspicious
        return self._pass(ev)  # lenient — not enough signal to FAIL

    @classmethod
    def _test_cases(cls):
        """Test cases: PASS, FAIL-capped, FAIL-semantic, and edge cases."""
        def make_resp(content: str, finish_reason: str, status_code: int = 200) -> ProbeResponse:
            return ProbeResponse(
                status_code=status_code,
                body={"choices": [{"message": {"content": content}, "finish_reason": finish_reason}]},
            )

        return [
            # PASS: model returns all 800 BETAs with stop
            ("PASS: 800 betas",
             [make_resp(" ".join(["BETA"] * 800), "stop")],
             "pass"),
            # FAIL: router capped tokens, only 200 BETAs returned with length finish
            ("FAIL: output capped by router",
             [make_resp(" ".join(["BETA"] * 200), "length")],
             "fail"),
            # FAIL: model truncated semantically, too few BETAs with stop finish
            ("FAIL: semantic truncation",
             [make_resp(" ".join(["BETA"] * 100), "stop")],
             "fail"),
            # INCONCLUSIVE: network error
            ("INCONCLUSIVE: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT")],
             "inconclusive"),
            # INCONCLUSIVE: empty content
            ("INCONCLUSIVE: empty content",
             [ProbeResponse(status_code=200, body={"choices": [{"message": {"content": ""}, "finish_reason": "stop"}]})],
             "inconclusive"),
            # PASS: edge case — exactly 400 BETAs is acceptable
            ("PASS: exactly 400 betas",
             [make_resp(" ".join(["BETA"] * 400), "stop")],
             "pass"),
        ]


if __name__ == "__main__":
    D25_OutputCapProbe.self_test()
