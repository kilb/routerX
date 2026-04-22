"""D95 ResponseDeduplication -- detect cached/template responses.

Sends three semantically similar but differently worded prompts.  A real
model produces varied completions; a dishonest router returning from a
pre-generated cache yields byte-identical or near-identical answers.

Checks both exact byte equality (after whitespace strip) and Jaccard
word-level similarity > 0.95 between any pair.
"""
from __future__ import annotations

import itertools

from ..models import (
    DetectorResult,
    JudgeMode,
    Priority,
    ProbeRequest,
    ProbeResponse,
)
from ..registry import BaseDetector, detector

_PROMPTS = [
    "What is machine learning?",
    "Explain ML in simple terms",
    "Define machine learning for a beginner",
]
JACCARD_THRESHOLD = 0.98
MIN_VALID_RESPONSES = 2


@detector
class D95_ResponseDeduplication(BaseDetector):
    detector_id = "D95"
    detector_name = "ResponseDeduplication"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = 3
    description = "Detect cached or templated identical responses to varied prompts"

    async def send_probes(self) -> list[ProbeResponse]:
        probes = [ProbeRequest(
            payload={
                "model": self.config.claimed_model,
                "temperature": 0.3,
                "max_tokens": 150,
                "messages": [{"role": "user", "content": p}],
            },
            endpoint_path=self.config.default_endpoint_path,
            description=f"D95 dedup probe {i}",
        ) for i, p in enumerate(_PROMPTS)]
        return await self.client.send_concurrent(probes)

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        contents: list[str] = []
        for r in responses:
            if r.is_network_error or r.status_code != 200:
                continue
            c = r.content
            if c:
                contents.append(c)

        if len(contents) < MIN_VALID_RESPONSES:
            return self._inconclusive(
                f"only {len(contents)} valid responses, need {MIN_VALID_RESPONSES}"
            )

        stripped = [c.strip() for c in contents]
        evidence: dict = {"response_previews": [c[:100] for c in stripped]}

        # If all responses are very short, similarity is meaningless —
        # short outputs naturally share most words. Not evidence of caching.
        avg_len = sum(len(c) for c in stripped) / len(stripped)
        if avg_len < 50:
            return self._pass(evidence | {
                "note": f"responses too short (avg {avg_len:.0f} chars) "
                        f"for meaningful deduplication check",
            })

        # Check byte-identical pairs
        for i, j in itertools.combinations(range(len(stripped)), 2):
            if stripped[i] == stripped[j]:
                evidence["identical_pair"] = (i, j)
                return self._fail(
                    f"responses {i} and {j} are byte-identical",
                    evidence,
                )

        # Check Jaccard word similarity
        word_sets = [set(c.lower().split()) for c in stripped]
        for i, j in itertools.combinations(range(len(word_sets)), 2):
            union = word_sets[i] | word_sets[j]
            if not union:
                continue
            jaccard = len(word_sets[i] & word_sets[j]) / len(union)
            if jaccard > JACCARD_THRESHOLD:
                evidence["high_jaccard_pair"] = (i, j)
                evidence["jaccard"] = f"{jaccard:.3f}"
                return self._fail(
                    f"responses {i} and {j} have Jaccard similarity "
                    f"{jaccard:.3f} > {JACCARD_THRESHOLD}",
                    evidence,
                )

        return self._pass(evidence)

    @classmethod
    def _test_cases(cls):
        def _resp(content: str) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={
                    "choices": [{
                        "message": {"role": "assistant", "content": content},
                        "finish_reason": "stop",
                    }],
                },
            )

        return [
            ("PASS: different responses",
             [_resp("ML is a subset of AI that learns from data."),
              _resp("Machine learning allows computers to improve from experience."),
              _resp("It is a branch of artificial intelligence focused on patterns.")],
             "pass"),
            ("FAIL: all identical (substantive length)",
             [_resp("Machine learning is a branch of artificial intelligence that enables computers to learn from data and improve their performance on specific tasks without being explicitly programmed for every scenario.")] * 3,
             "fail"),
            ("INCONCLUSIVE: not enough valid responses",
             [ProbeResponse(status_code=0, error="TIMEOUT"),
              ProbeResponse(status_code=0, error="TIMEOUT"),
              _resp("some answer")],
             "inconclusive"),
            ("FAIL: near-identical (high Jaccard > 0.98)",
             [_resp(
                 # ~200 unique words; only last word differs ("testing" vs
                 # "evaluating") yielding Jaccard ~0.99 > 0.98 threshold.
                 "Machine learning is a branch of artificial intelligence "
                 "that enables computers to learn from very large data sets "
                 "and improve their performance on tasks without being "
                 "explicitly programmed. It uses statistical methods to "
                 "find patterns in data. Models are trained on examples "
                 "and then make predictions on new inputs. Deep learning "
                 "is a subset that uses neural networks with many layers. "
                 "Applications include image recognition speech processing "
                 "natural language understanding recommendation systems "
                 "autonomous vehicles medical diagnosis fraud detection "
                 "weather forecasting stock analysis robot control game "
                 "playing drug discovery protein folding translation "
                 "summarization sentiment analysis topic modeling "
                 "clustering regression classification reinforcement "
                 "optimization search ranking filtering generation "
                 "compression encryption simulation rendering mining "
                 "extraction transformation loading indexing querying "
                 "caching routing scheduling balancing monitoring logging "
                 "alerting reporting visualization dashboarding analytics "
                 "tracking measuring profiling benchmarking planning "
                 "designing architecting implementing deploying maintaining "
                 "scaling distributing replicating partitioning sharding "
                 "aggregating normalizing validating sanitizing escaping "
                 "encoding decoding serializing deserializing marshalling "
                 "unmarshalling compiling interpreting transpiling linking "
                 "bundling minifying obfuscating debugging inspecting "
                 "refactoring restructuring migrating upgrading patching "
                 "versioning tagging branching merging rebasing cherry "
                 "picking squashing releasing publishing containerizing "
                 "orchestrating provisioning configuring automating testing."
             ), _resp(
                 "Machine learning is a branch of artificial intelligence "
                 "that enables computers to learn from very large data sets "
                 "and improve their performance on tasks without being "
                 "explicitly programmed. It uses statistical methods to "
                 "find patterns in data. Models are trained on examples "
                 "and then make predictions on new inputs. Deep learning "
                 "is a subset that uses neural networks with many layers. "
                 "Applications include image recognition speech processing "
                 "natural language understanding recommendation systems "
                 "autonomous vehicles medical diagnosis fraud detection "
                 "weather forecasting stock analysis robot control game "
                 "playing drug discovery protein folding translation "
                 "summarization sentiment analysis topic modeling "
                 "clustering regression classification reinforcement "
                 "optimization search ranking filtering generation "
                 "compression encryption simulation rendering mining "
                 "extraction transformation loading indexing querying "
                 "caching routing scheduling balancing monitoring logging "
                 "alerting reporting visualization dashboarding analytics "
                 "tracking measuring profiling benchmarking planning "
                 "designing architecting implementing deploying maintaining "
                 "scaling distributing replicating partitioning sharding "
                 "aggregating normalizing validating sanitizing escaping "
                 "encoding decoding serializing deserializing marshalling "
                 "unmarshalling compiling interpreting transpiling linking "
                 "bundling minifying obfuscating debugging inspecting "
                 "refactoring restructuring migrating upgrading patching "
                 "versioning tagging branching merging rebasing cherry "
                 "picking squashing releasing publishing containerizing "
                 "orchestrating provisioning configuring automating evaluating."
             ), _resp(
                 "Quantum physics is a fundamental theory in physics."
             )],
             "fail"),
        ]


if __name__ == "__main__":
    D95_ResponseDeduplication.self_test()
