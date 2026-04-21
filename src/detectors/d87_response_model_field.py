"""D87 ResponseModelFieldAudit -- model mismatch, fallback switch, fabricated timestamp.

Sends 3 identical lightweight requests and inspects the ``model`` and
``created`` fields in each response. Catches routers that return a
different model than requested, silently switch models between calls
(fallback routing), or return stale/fabricated timestamps.
"""
from __future__ import annotations

import time

from ..models import (
    DetectorResult,
    JudgeMode,
    Priority,
    ProbeRequest,
    ProbeResponse,
)
from ..registry import BaseDetector, detector

_N = 3
MAX_TIMESTAMP_DRIFT_S = 3600  # 1 hour


def _model_matches(claimed: str, returned: str) -> bool:
    """Check if models refer to the same family, ignoring word order and dates.

    Allow date-suffix flexibility: ``gpt-4o`` matches ``gpt-4o-2024-08-06``.
    Also handle word-order differences like ``claude-opus-4.6`` vs
    ``claude-4.6-opus-20260205`` by keyword-set equality after stripping
    vendor prefixes and date suffixes.
    """
    import re

    # Strip trailing date suffixes: -2024-08-06, -20240806
    date_re = re.compile(r"(-\d{4}-\d{2}-\d{2}|-\d{8})$")
    c = date_re.sub("", claimed).lower().strip()
    r = date_re.sub("", returned).lower().strip()
    if c == r:
        return True
    # Keyword-set comparison: same tokens in any order → match.
    # This handles claude-opus-4.6 vs claude-4.6-opus.
    _VENDOR_NOISE = {"", "anthropic", "openai", "google"}
    c_parts = set(re.split(r"[/\-]", c)) - _VENDOR_NOISE
    r_parts = set(re.split(r"[/\-]", r)) - _VENDOR_NOISE
    if c_parts and r_parts and c_parts == r_parts:
        return True
    return False


@detector
class D87_ResponseModelFieldAudit(BaseDetector):
    detector_id = "D87"
    detector_name = "ResponseModelFieldAudit"
    priority = Priority.P2
    judge_mode = JudgeMode.ONCE
    request_count = _N
    description = (
        "Detect model field mismatch, silent fallback switching, "
        "and fabricated timestamps in responses."
    )

    async def send_probes(self) -> list[ProbeResponse]:
        probes = [
            ProbeRequest(
                payload={
                    "model": self.config.claimed_model,
                    "max_tokens": 5,
                    "temperature": 0,
                    "messages": [
                        {"role": "user", "content": "Reply with just 'ok'."}
                    ],
                },
                endpoint_path=self.config.default_endpoint_path,
                description=f"D87 model field probe {i}",
            )
            for i in range(_N)
        ]
        return await self.client.send_concurrent(probes)

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        now = time.time()
        claimed = self.config.claimed_model

        models: list[str] = []
        timestamps: list[int] = []

        for r in responses:
            if r.is_network_error or r.status_code != 200 or not r.body:
                continue
            model_val = r.body.get("model")
            if model_val and isinstance(model_val, str):
                models.append(model_val)
            created_val = r.body.get("created")
            if isinstance(created_val, (int, float)):
                timestamps.append(int(created_val))

        ev: dict = {
            "claimed_model": claimed,
            "response_models": models,
            "timestamps": timestamps,
        }

        if len(models) < 2:
            return self._inconclusive("not enough responses with model field")

        # Check 1: model mismatch against claimed model
        for m in models:
            if not _model_matches(claimed, m):
                ev["mismatched_model"] = m
                return self._fail(
                    f"response model '{m}' does not match claimed '{claimed}'",
                    ev,
                )

        # Check 2: model inconsistency across responses (fallback switching).
        # Use the same base-name stripping as Check 1: date suffixes like
        # -2024-08-06 vs -2024-05-13 are normal OpenAI snapshot rotation.
        import re as _re
        _date_pat = _re.compile(r"(-\d{4}-\d{2}-\d{2}|-\d{8})$")
        base_names = {_date_pat.sub("", m.lower().strip()) for m in models}
        if len(base_names) > 1:
            ev["unique_base_models"] = sorted(base_names)
            return self._fail(
                f"model base names differ across responses: {sorted(base_names)} "
                "-- possible silent fallback routing",
                ev,
            )

        # Check 3: fabricated/stale timestamp
        for ts in timestamps:
            drift = abs(now - ts)
            if drift > MAX_TIMESTAMP_DRIFT_S:
                ev["bad_timestamp"] = ts
                ev["drift_seconds"] = int(drift)
                return self._fail(
                    f"created timestamp {ts} is off by {int(drift)}s "
                    "(>1 hour) -- likely fabricated or cached",
                    ev,
                )

        return self._pass(ev)

    @classmethod
    def _test_cases(cls):
        def mk(model: str, created: int | None = None) -> dict:
            body: dict = {"model": model, "choices": [
                {"message": {"content": "ok"}, "finish_reason": "stop"},
            ]}
            if created is not None:
                body["created"] = created
            return body

        def r(model: str, ts: int | None = None) -> ProbeResponse:
            return ProbeResponse(status_code=200, body=mk(model, ts))

        now = int(time.time())
        ok_model = "gpt-4o-2024-08-06"
        no_model = {"choices": [{"message": {"content": "ok"}}]}

        return [
            ("PASS: matching model and fresh timestamp",
             [r(ok_model, now), r(ok_model, now + 1), r(ok_model, now + 2)], "pass"),
            ("FAIL: response model is gpt-4o-mini when claimed gpt-4o",
             [r("gpt-4o-mini-2024-07-18", now) for _ in range(3)], "fail"),
            # Different date suffixes (2024-08-06 vs 2024-05-13) have the same
            # base name "gpt-4o" -- OpenAI legitimately rotates snapshot dates,
            # so this should PASS.
            ("PASS: same base model with different date suffixes",
             [r(ok_model, now), r("gpt-4o-2024-05-13", now), r(ok_model, now)], "pass"),
            # Word-order difference: e.g. date-suffixed reorder (gpt-4o vs 4o-gpt)
            # tested via _model_matches function directly; self_test uses gpt-4o as claimed
            # Different base models: "gpt-4o" vs "gpt-4o-mini" -- real switching
            ("FAIL: different base models across responses",
             [r(ok_model, now), r("gpt-4o-mini-2024-07-18", now), r(ok_model, now)], "fail"),
            ("FAIL: created timestamp from 2020",
             [r(ok_model, 1580000000 + i) for i in range(3)], "fail"),
            ("INCONCLUSIVE: no model field",
             [ProbeResponse(status_code=200, body=no_model) for _ in range(3)],
             "inconclusive"),
            ("INCONCLUSIVE: all network errors",
             [ProbeResponse(status_code=0, error="TIMEOUT") for _ in range(3)],
             "inconclusive"),
        ]


if __name__ == "__main__":
    D87_ResponseModelFieldAudit.self_test()
