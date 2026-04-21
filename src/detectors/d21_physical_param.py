from __future__ import annotations

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProviderType, ProbeRequest, ProbeResponse, DetectorResult
from ..tokenizer import token_counter
from ..config import LOGIT_BIAS_CANDIDATES
from ..utils.text_analysis import readable_bigram_ratio

BIGRAM_THRESHOLD = 0.75
MIN_FAIL_COUNT = 2


@detector
class D21_PhysicalParamProbe(BaseDetector):
    detector_id = "D21"
    detector_name = "PhysicalParamProbe"
    priority = Priority.P0
    judge_mode = JudgeMode.ONCE
    request_count = 5
    description = "Detect web reverse proxy by checking physical parameter blindspots"

    async def send_probes(self) -> list[ProbeResponse]:
        model = self.config.claimed_model
        ep = self.config.default_endpoint_path

        probe_a = ProbeRequest(
            payload={"model": model, "temperature": 2.0, "max_tokens": 100,
                     "messages": [{"role": "user", "content": "Describe the history of artificial intelligence."}]},
            endpoint_path=ep, description="21a: temp=2.0")

        ban = token_counter.find_single_token(LOGIT_BIAS_CANDIDATES, model)
        probe_b = None
        if ban:
            word, tid = ban
            probe_b = ProbeRequest(
                payload={"model": model, "temperature": 0.2, "max_tokens": 200,
                         "logit_bias": {str(tid): -100},
                         "messages": [{"role": "user",
                                       "content": f"Write 5 short sentences about apples. Every sentence must contain the word '{word.strip()}'."}]},
                endpoint_path=ep, description=f"21b: ban '{word}'")

        probe_c = ProbeRequest(
            payload={"model": model, "temperature": 0, "max_tokens": 8,
                     "logprobs": True, "top_logprobs": 5,
                     "messages": [{"role": "user", "content": "Answer with exactly one token: YES"}]},
            endpoint_path=ep, description="21c: logprobs")

        probe_base = ProbeRequest(
            payload={"model": model, "max_tokens": 100,
                     "messages": [{"role": "user", "content": "Tell me a joke"}]},
            endpoint_path=ep, description="21d: baseline")

        probe_d = ProbeRequest(
            payload={"model": model, "max_tokens": 1,
                     "messages": [{"role": "user", "content": "Explain the fundamental principles of quantum mechanics in detail."}]},
            endpoint_path=ep, description="21d: max_tokens=1")

        sendable = [p for p in [probe_a, probe_b, probe_c, probe_base, probe_d] if p is not None]
        results = await self.client.send_concurrent(sendable)

        if probe_b is None:
            # Insert a synthetic error response at index 1 for the missing ban probe
            results.insert(1, ProbeResponse(status_code=0, error="no single-token word"))
        return results

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r_a, r_b, r_c, r_base, r_d = responses
        subs = []
        ban = token_counter.find_single_token(LOGIT_BIAS_CANDIDATES, self.config.claimed_model)
        ban_word = ban[0].strip() if ban else ""
        # 21a: temp=2.0
        if r_a.is_network_error:
            subs.append(("21a_temp", None, "network error"))
        else:
            ratio = readable_bigram_ratio(r_a.content)
            ok = ratio < BIGRAM_THRESHOLD
            subs.append(("21a_temp", ok, f"bigram={ratio:.2f}"))
        # 21b: logit_bias (OpenAI-only; skip for Anthropic/Gemini but run
        # for ANY since we can't rule out an OpenAI backend).
        _skip_oai_params = (
            self.config.claimed_provider in (ProviderType.ANTHROPIC, ProviderType.GEMINI)
            or any(k in self.config.claimed_model.lower() for k in ("claude", "gemini", "llama", "qwen", "mistral"))
        )
        if _skip_oai_params:
            subs.append(("21b_logit", None, "skipped: logit_bias not supported by provider"))
        elif r_b.is_network_error:
            subs.append(("21b_logit", None, r_b.error or "error"))
        elif ban_word:
            found = ban_word.lower() in r_b.content.lower()
            subs.append(("21b_logit", not found, f"banned '{ban_word}' {'found' if found else 'absent'}"))
        else:
            subs.append(("21b_logit", None, "no ban word"))
        # 21c: logprobs (OpenAI-only; skip for Anthropic/Gemini)
        if _skip_oai_params:
            subs.append(("21c_logprobs", None, "skipped: logprobs not supported by provider"))
        elif r_c.is_network_error:
            subs.append(("21c_logprobs", None, "network error"))
        elif r_c.body:
            lp = None
            try:
                lp = r_c.body["choices"][0]["logprobs"]
            except (KeyError, IndexError, TypeError):
                pass
            subs.append(("21c_logprobs", lp is not None, "present" if lp else "missing"))
        else:
            subs.append(("21c_logprobs", False, "no body"))
        # 21d: max_tokens=1
        if r_d.is_network_error or r_base.is_network_error:
            subs.append(("21d_max1", None, "network error"))
        else:
            tok_count = len(r_d.content.split()) if r_d.content else 0
            ratio = r_d.latency_ms / max(r_base.latency_ms, 1)
            failed = ratio > 0.8 or tok_count > 3 or r_d.finish_reason != "length"
            subs.append(("21d_max1", not failed, f"ratio={ratio:.2f} toks={tok_count} fr={r_d.finish_reason}"))
        fail_n = sum(1 for _, p, _ in subs if p is False)
        pass_n = sum(1 for _, p, _ in subs if p is True)
        ev = {"sub_probes": [{"name": n, "passed": p, "detail": d} for n, p, d in subs], "fail_count": fail_n}
        if fail_n >= MIN_FAIL_COUNT:
            return self._fail(f"{fail_n}/4 sub-probes failed", ev)
        if pass_n == 0:
            return self._inconclusive("no sub-probe produced a definitive result")
        return self._pass(ev)

    @classmethod
    def _test_cases(cls):
        ok = ProbeResponse(status_code=200, body={"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]})
        lp_ok = ProbeResponse(status_code=200, body={"choices": [{"message": {"content": "YES"}, "finish_reason": "stop", "logprobs": {"content": [{"token": "YES", "logprob": -0.01}]}}]})
        lp_miss = ProbeResponse(status_code=200, body={"choices": [{"message": {"content": "YES"}, "finish_reason": "stop"}]})
        # Chaotic text (low bigram ratio)
        chaotic = ProbeResponse(status_code=200, body={"choices": [{"message": {"content": "xkl wq zpm brt fng dlk yyy aaa"}, "finish_reason": "stop"}]})
        # Very fluent text (high bigram ratio = many adjacent common-word pairs) - FAIL for 21a
        fluent = ProbeResponse(status_code=200, body={"choices": [{"message": {"content": "I have the is a to the of and this is the of in the is the to for the of it is that the"}, "finish_reason": "stop"}]})
        fast = ProbeResponse(status_code=200, body={"choices": [{"message": {"content": "Q"}, "finish_reason": "length"}]}, latency_ms=50)
        slow = ProbeResponse(status_code=200, body={"choices": [{"message": {"content": "Q"}, "finish_reason": "length"}]}, latency_ms=500)
        base = ProbeResponse(status_code=200, body={"choices": [{"message": {"content": "joke"}, "finish_reason": "stop"}]}, latency_ms=500)
        return [
            ("PASS: all sub-probes pass", [chaotic, ok, lp_ok, base, fast], "pass"),
            ("FAIL: 21a fluent + 21c no logprobs", [fluent, ok, lp_miss, base, fast], "fail"),
            ("FAIL: 21a fluent + 21d slow", [fluent, ok, lp_ok, base, slow], "fail"),
            ("INCONCLUSIVE: all network error", [ProbeResponse(status_code=0, error="T")] * 5, "inconclusive"),
        ]


if __name__ == "__main__":
    D21_PhysicalParamProbe.self_test()
