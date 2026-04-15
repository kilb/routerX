from __future__ import annotations

import random
import string

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProbeRequest, ProbeResponse, DetectorResult
from ..tokenizer import token_counter
from ..config import TOKENIZER_FINGERPRINTS, TOKENIZER_PROBE_STRINGS

FALLBACK_CONFIDENCE = 0.50

# Default probe word used only in self-test when send_probes hasn't run.
_TEST_PROBE_WORD = "SolidGoldMagikarp"


def _make_runtime_probe_pool() -> list[str]:
    """Return the static pool plus one randomly generated string per invocation."""
    pool = list(TOKENIZER_PROBE_STRINGS)
    # Append a random alphanumeric string that changes every run --
    # impossible to whitelist without blanket-matching all words.
    rand_str = "".join(random.choices(string.ascii_letters + string.digits, k=12))
    pool.append(rand_str)
    return pool


def _identify_family(tokens: list[str], probe_word: str) -> str | None:
    """Return a matching tokenizer family name from TOKENIZER_FINGERPRINTS, or None."""
    candidates = TOKENIZER_FINGERPRINTS.get(probe_word, {})
    for family, expected in candidates.items():
        if tokens == expected:
            return family
    return None


def _extract_logprob_tokens(body: dict) -> list[str] | None:
    """Extract token strings from logprobs.content in an OpenAI response body."""
    try:
        lp_content = body["choices"][0]["logprobs"]["content"]
        if not isinstance(lp_content, list) or not lp_content:
            return None
        return [item["token"] for item in lp_content]
    except (KeyError, IndexError, TypeError):
        return None


def _parse_selftest_tokens(content: str) -> list[str]:
    """Parse model self-report: one token per line, strip whitespace."""
    return [line.strip() for line in content.splitlines() if line.strip()]


@detector
class D4a_TokenizerFingerprint(BaseDetector):
    detector_id = "D4a"
    detector_name = "TokenizerFingerprint"
    priority = Priority.P0
    judge_mode = JudgeMode.ONCE
    request_count = 1
    description = "Detect model family substitution via tokenizer boundary fingerprinting"

    async def send_probes(self) -> list[ProbeResponse]:
        """Send a logprobs probe for a randomly-chosen fingerprint word.

        Picks from TOKENIZER_PROBE_STRINGS so a router cannot whitelist the
        specific word ``SolidGoldMagikarp``. All words in the pool are
        equally useful for tokenizer-family discrimination.
        """
        self._probe_word = random.choice(_make_runtime_probe_pool())
        return [await self.client.send(ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "temperature": 0,
                "max_tokens": 10,
                "logprobs": True,
                "top_logprobs": 1,
                "messages": [{"role": "user", "content": (
                    f"Repeat exactly without any changes: {self._probe_word}"
                )}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description="tokenizer fingerprint probe (logprobs)",
        ))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        """Compare observed token boundaries to claimed-model tokenization."""
        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error or "network error")
        if r.status_code != 200:
            return self._inconclusive(f"status {r.status_code}")

        # Primary path: logprobs present in body
        if r.body:
            observed = _extract_logprob_tokens(r.body)
            if observed:
                return self._compare_tokens(observed, confidence_if_fail=1.0)

        # Fallback path: ask model to self-tokenize (lower confidence)
        content = r.content
        if not content:
            return self._inconclusive("no logprobs and empty content")
        observed = _parse_selftest_tokens(content)
        if not observed:
            return self._inconclusive("could not parse self-tokenization response")
        return self._compare_tokens(observed, confidence_if_fail=FALLBACK_CONFIDENCE)

    def _compare_tokens(
        self, observed: list[str], *, confidence_if_fail: float
    ) -> DetectorResult:
        """Core comparison: observed tokens vs expected for claimed model."""
        claimed_model = self.config.claimed_model
        probe_word = getattr(self, "_probe_word", _TEST_PROBE_WORD)
        expected = token_counter.tokenize(probe_word, model=claimed_model)

        if observed == expected:
            return self._pass({
                "probe_word": probe_word,
                "tokens": observed,
                "claimed_model": claimed_model,
            })

        # Mismatch: attempt to identify actual family
        actual_family = _identify_family(observed, probe_word)
        evidence = {
            "probe_word": probe_word,
            "claimed_model": claimed_model,
            "expected_tokens": expected,
            "observed_tokens": observed,
            "identified_family": actual_family,
        }
        return self._fail("tokenizer mismatch", evidence, confidence=confidence_if_fail)

    @classmethod
    def _test_cases(cls):
        def make_logprob_resp(tokens: list[str]) -> ProbeResponse:
            lp_content = [{"token": t, "logprob": -0.1, "top_logprobs": []} for t in tokens]
            return ProbeResponse(
                status_code=200,
                body={
                    "choices": [{
                        "message": {"content": "".join(tokens)},
                        "finish_reason": "stop",
                        "logprobs": {"content": lp_content},
                    }]
                },
            )

        def make_selftest_resp(token_lines: list[str]) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={
                    "choices": [{
                        "message": {"content": "\n".join(token_lines)},
                        "finish_reason": "stop",
                    }]
                },
            )

        # tiktoken for gpt-4o actually uses cl100k: ["Solid", "Gold", "Mag", "ik", "arp"]
        # Test PASS cases must use what tiktoken actually returns for the test
        # harness's claimed_model = "gpt-4o".
        actual_expected = token_counter.tokenize(_TEST_PROBE_WORD, model="gpt-4o")

        return [
            # PASS: logprobs tokens match claimed model's tokenizer
            ("PASS: logprobs match expected tokenizer",
             [make_logprob_resp(actual_expected)],
             "pass"),
            # FAIL: logprobs show completely different boundaries
            ("FAIL: logprobs show different tokenizer family",
             [make_logprob_resp(["So", "li", "dGo", "ld", "Ma", "gi", "ka", "rp"])],
             "fail"),
            # PASS: no logprobs but self-tokenize matches
            ("PASS: self-tokenize fallback matches",
             [make_selftest_resp(actual_expected)],
             "pass"),
            # FAIL: self-tokenize returns wrong boundaries
            ("FAIL: self-tokenize shows different boundaries",
             [make_selftest_resp(["So", "li", "d", "Go", "ld", "Ma", "gi", "ka", "rp"])],
             "fail"),
            # INCONCLUSIVE: network error
            ("INCONCLUSIVE: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT")],
             "inconclusive"),
            # INCONCLUSIVE: non-200 status
            ("INCONCLUSIVE: 503 status",
             [ProbeResponse(status_code=503, body=None)],
             "inconclusive"),
            # INCONCLUSIVE: no logprobs and empty content
            ("INCONCLUSIVE: no logprobs, empty content",
             [ProbeResponse(status_code=200, body={"choices": [{"message": {"content": ""}, "finish_reason": "stop"}]})],
             "inconclusive"),
        ]


if __name__ == "__main__":
    D4a_TokenizerFingerprint.self_test()
