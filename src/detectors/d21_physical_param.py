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
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = 5
    detector_timeout = 60.0
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
        model_lower = self.config.claimed_model.lower()
        _is_openai_native = (
            any(k in model_lower for k in ("gpt", "o1", "o3", "o4"))
            and not any(k in model_lower for k in ("claude", "gemini", "llama", "qwen", "mistral"))
        )
        # 21a: temp=2.0
        # Non-OpenAI providers often clamp temperature to [0,1] — a clamped
        # response looks "normal" but is a legitimate provider limitation,
        # not evidence of a reverse proxy ignoring the parameter.
        if not _is_openai_native:
            subs.append(("21a_temp", None, "skipped: temperature range varies by provider"))
        elif r_a.is_network_error or r_a.status_code != 200:
            subs.append(("21a_temp", None, r_a.error_detail if r_a.status_code != 200 else "network error"))
        elif not r_a.content or len(r_a.content.split()) < 5:
            subs.append(("21a_temp", None, "response too short for bigram analysis"))
        else:
            ratio = readable_bigram_ratio(r_a.content)
            ok = ratio < BIGRAM_THRESHOLD
            subs.append(("21a_temp", ok, f"bigram={ratio:.2f}"))
        # 21b/21c: logit_bias and logprobs are OpenAI-native capabilities.
        # Non-OpenAI backend models don't support them — a proxy can't
        # translate capabilities the backend model lacks.
        _skip_oai_params = not _is_openai_native
        if _skip_oai_params:
            subs.append(("21b_logit", None, "skipped: logit_bias not supported by provider"))
        elif r_b.is_network_error or r_b.status_code != 200:
            subs.append(("21b_logit", None, r_b.error_detail if r_b.status_code != 200 else (r_b.error or "error")))
        elif ban_word:
            found = ban_word.lower() in r_b.content.lower()
            subs.append(("21b_logit", not found, f"banned '{ban_word}' {'found' if found else 'absent'}"))
        else:
            subs.append(("21b_logit", None, "no ban word"))
        # 21c: logprobs (OpenAI-only; skip for Anthropic/Gemini)
        if _skip_oai_params:
            subs.append(("21c_logprobs", None, "skipped: logprobs not supported by provider"))
        elif r_c.is_network_error or r_c.status_code != 200:
            subs.append(("21c_logprobs", None, r_c.error_detail if r_c.status_code != 200 else "network error"))
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
        if r_d.is_network_error or r_base.is_network_error or r_d.status_code != 200 or r_base.status_code != 200:
            detail = next((r.error_detail for r in (r_d, r_base) if r.status_code != 200), "network error")
            subs.append(("21d_max1", None, detail))
        else:
            tok_count = len(r_d.content.split()) if r_d.content else 0
            ratio = r_d.latency_ms / max(r_base.latency_ms, 1)
            # finish_reason=None or empty content means response was
            # malformed — treat as inconclusive, not failure
            if not r_d.content or r_d.finish_reason is None:
                subs.append(("21d_max1", None, f"malformed response (fr={r_d.finish_reason})"))
            else:
                # max_tokens=1 is honored if: output is short AND finish_reason=length.
                # Latency ratio alone is unreliable — proxy overhead dominates
                # when the actual generation is just 1 token.
                if tok_count <= 3 and r_d.finish_reason == "length":
                    failed = False  # max_tokens clearly honored
                else:
                    failed = tok_count > 3 or r_d.finish_reason != "length"
                subs.append(("21d_max1", not failed, f"ratio={ratio:.2f} toks={tok_count} fr={r_d.finish_reason}"))
        fail_n = sum(1 for _, p, _ in subs if p is False)
        pass_n = sum(1 for _, p, _ in subs if p is True)
        ev = {"sub_probes": [{"name": n, "passed": p, "detail": d} for n, p, d in subs], "fail_count": fail_n}
        if fail_n >= MIN_FAIL_COUNT:
            return self._fail(f"{fail_n}/4 sub-probes failed", ev)
        if pass_n == 0:
            return self._pass({"note": "no sub-probe produced a definitive result"})
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
        # 21d fail: too many tokens (max_tokens=1 not honored) + wrong finish_reason
        d_bad = ProbeResponse(status_code=200, body={"choices": [{"message": {"content": "Here is a long answer"}, "finish_reason": "stop"}]}, latency_ms=500)
        base = ProbeResponse(status_code=200, body={"choices": [{"message": {"content": "joke"}, "finish_reason": "stop"}]}, latency_ms=500)
        return [
            ("PASS: all sub-probes pass", [chaotic, ok, lp_ok, base, fast], "pass"),
            ("FAIL: 21a fluent + 21c no logprobs", [fluent, ok, lp_miss, base, fast], "fail"),
            ("FAIL: 21a fluent + 21d too many tokens", [fluent, ok, lp_ok, base, d_bad], "fail"),
            ("PASS: all network error", [ProbeResponse(status_code=0, error="T")] * 5, "pass"),
        ]


if __name__ == "__main__":
    D21_PhysicalParamProbe.self_test()
