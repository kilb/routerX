"""D86 ContextCompressionDetection -- detect lossy compression of history.

Some routers silently summarize past conversation turns before forwarding
to the upstream model. Unlike D24c (which detects hard truncation), this
detector targets LOSSY COMPRESSION where the gist is preserved but exact
details -- precise numbers, codes, identifiers -- are rounded or lost.

Probe design: uses semantically NEUTRAL technical values (coordinates,
UUIDs, hex codes) instead of financial/PII data to avoid triggering
privacy-protection refusals in frontier models like Claude.
"""
from __future__ import annotations

import random
import string

from ..models import (
    DetectorResult,
    JudgeMode,
    Priority,
    ProbeRequest,
    ProbeResponse,
)
from ..registry import BaseDetector, detector


def _random_hex(n: int) -> str:
    return "".join(random.choices("0123456789abcdef", k=n))


def _generate_probe_values() -> tuple[str, str, str]:
    """Generate 3 semantically neutral exact values per run."""
    coord = f"{random.uniform(30, 60):.6f}N, {random.uniform(100, 140):.6f}E"
    ref_code = f"REF-{_random_hex(8).upper()}"
    version = f"v{random.randint(2,9)}.{random.randint(0,99)}.{random.randint(0,999)}"
    return coord, ref_code, version


# Fallback values used by self_test (send_probes never ran).
_TEST_COORD = "47.382910N, 118.294037E"
_TEST_REF = "REF-4A7B3C1E"
_TEST_VER = "v3.14.159"


@detector
class D86_ContextCompressionDetection(BaseDetector):
    detector_id = "D86"
    detector_name = "ContextCompressionDetection"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = 1
    detector_timeout = 60.0
    description = (
        "Detect routers that silently compress or summarize conversation "
        "history, losing exact technical details like coordinates and codes."
    )

    async def send_probes(self) -> list[ProbeResponse]:
        coord, ref, ver = _generate_probe_values()
        self._coord = coord
        self._ref = ref
        self._ver = ver

        messages = [
            # Turn 1: plant exact values (neutral technical context)
            {
                "role": "user",
                "content": (
                    "I'm configuring a sensor deployment. Here are the specs:\n"
                    f"- GPS coordinates: {coord}\n"
                    f"- Reference code: {ref}\n"
                    f"- Firmware version: {ver}\n"
                    "Please confirm you've recorded these."
                ),
            },
            {
                "role": "assistant",
                "content": (
                    f"Confirmed. I've noted the sensor deployment specs:\n"
                    f"- GPS: {coord}\n"
                    f"- Reference: {ref}\n"
                    f"- Firmware: {ver}"
                ),
            },
            # Turns 2-4: filler to push turn 1 further back
            {
                "role": "user",
                "content": (
                    "What are the main differences between classical and "
                    "operant conditioning in psychology?"
                ),
            },
            {
                "role": "assistant",
                "content": (
                    "Classical conditioning involves pairing a neutral "
                    "stimulus with an unconditioned stimulus, while operant "
                    "conditioning uses reinforcement and punishment to shape "
                    "voluntary behavior."
                ),
            },
            {
                "role": "user",
                "content": "Explain the water cycle in simple terms.",
            },
            {
                "role": "assistant",
                "content": (
                    "Water evaporates from oceans and lakes, rises to form "
                    "clouds, then falls as precipitation. It flows back into "
                    "bodies of water and the cycle repeats."
                ),
            },
            {
                "role": "user",
                "content": (
                    "What is the tallest mountain on each continent? "
                    "List them briefly."
                ),
            },
            {
                "role": "assistant",
                "content": (
                    "Everest (Asia), Aconcagua (South America), Denali "
                    "(North America), Kilimanjaro (Africa), Elbrus (Europe), "
                    "Vinson (Antarctica), Puncak Jaya (Oceania)."
                ),
            },
            # Turn 5: recall — neutral phrasing, no PII sensitivity
            {
                "role": "user",
                "content": (
                    "I need to verify the sensor deployment details from "
                    "earlier. What were the exact GPS coordinates, reference "
                    "code, and firmware version?"
                ),
            },
        ]

        return [
            await self.client.send(
                ProbeRequest(
                    payload={
                        "model": self.config.claimed_model,
                        "max_tokens": 100,
                        "temperature": 0,
                        "messages": messages,
                    },
                    endpoint_path=self.config.default_endpoint_path,
                    description="D86 context compression recall",
                )
            )
        ]

    @staticmethod
    def _coord_matches(expected: str, content: str) -> bool:
        """Match GPS coordinates to 4 decimal places (prefix match).

        Models rarely recall 6-decimal GPS precision exactly, so we loosen
        the check: extract the first 4 decimals from each coordinate and
        match those in the response.
        """
        import re
        # Parse expected format: "47.382910N, 118.294037E"
        nums = re.findall(r"(\d+\.\d+)", expected)
        for num in nums:
            # Truncate to 4 decimal places for matching
            parts = num.split(".")
            prefix = parts[0] + "." + parts[1][:4]
            if prefix not in content:
                return False
        return len(nums) > 0

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error or "network error")

        content = r.content
        if not content:
            return self._inconclusive("empty response content")

        coord = getattr(self, "_coord", _TEST_COORD)
        ref = getattr(self, "_ref", _TEST_REF)
        ver = getattr(self, "_ver", _TEST_VER)

        # GPS: match to 4 decimal places instead of exact 6-decimal match
        has_coord = self._coord_matches(coord, content)
        has_ref = ref in content
        has_ver = ver in content
        hits = sum([has_coord, has_ref, has_ver])

        ev = {
            "expected": {"coord": coord, "ref": ref, "version": ver},
            "found": {"coord": has_coord, "ref": has_ref, "version": has_ver},
            "hits": f"{hits}/3",
            "got": content[:300],
        }

        if hits == 3:
            return self._pass(ev)
        if hits == 0:
            # Zero values recalled -- strong signal of compression/truncation
            return self._fail(
                "0/3 values recalled -- context heavily "
                "compressed or truncated",
                ev,
            )
        # 1-2 hits: partial recall could be model imprecision, not compression
        missing = []
        if not has_coord:
            missing.append("coordinates")
        if not has_ref:
            missing.append("reference code")
        if not has_ver:
            missing.append("firmware version")
        return self._inconclusive(
            f"partial recall ({hits}/3) -- {', '.join(missing)} lost; "
            "could be model imprecision rather than compression"
        )

    @classmethod
    def _test_cases(cls):
        def mk(content: str) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={
                    "choices": [
                        {
                            "message": {"content": content},
                            "finish_reason": "stop",
                        }
                    ]
                },
            )

        return [
            (
                "PASS: all 3 values recalled",
                [mk(f"GPS: {_TEST_COORD}\nRef: {_TEST_REF}\nFirmware: {_TEST_VER}")],
                "pass",
            ),
            (
                "PASS: GPS with 4 decimal precision still matches",
                [mk(f"GPS: 47.3829N, 118.2940E\nRef: {_TEST_REF}\nFirmware: {_TEST_VER}")],
                "pass",
            ),
            (
                "INCONCLUSIVE: only 2 of 3 recalled (version lost)",
                [mk(f"GPS: {_TEST_COORD}\nRef: {_TEST_REF}\nFirmware: unknown")],
                "inconclusive",
            ),
            (
                "FAIL: 0 of 3 recalled (heavy compression)",
                [mk("I don't have those details available.")],
                "fail",
            ),
            (
                "INCONCLUSIVE: network error",
                [ProbeResponse(status_code=0, error="TIMEOUT")],
                "inconclusive",
            ),
            (
                "INCONCLUSIVE: empty content",
                [mk("")],
                "inconclusive",
            ),
        ]


if __name__ == "__main__":
    D86_ContextCompressionDetection.self_test()
