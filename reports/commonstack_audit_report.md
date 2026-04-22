# Commonstack Router Audit Report

> **Endpoint:** `https://api.commonstack.ai/v1`  
> **Test Date:** 2026-04-23  
> **Models Tested:** 48/49  
> **Tool Version:** Router Auditor v0.1 (85 detectors)

## Summary

| Tier | Count | Description |
|------|-------|-------------|
| TIER_1 | 19 | No real issues detected |
| TIER_2 | 11 | Minor issues, generally usable |
| BLACKLIST | 18 | Significant parameter forwarding or security issues |

---

## 1. Parameter Forwarding Issues

### D62: logprobs Not Forwarded

**Severity:** P1 — Affects model debugging and verification  
**Affected Models (9):** gpt-4.1, gpt-4o-mini, gpt-5, gpt-5.2, gpt-5.3-codex, gpt-5.4, gpt-5.4-mini, gpt-5.4-nano, gpt-oss-120b

**Issue:** Requests with `logprobs: true` return responses without the `logprobs` field. Commonstack appears to strip this parameter before forwarding to the upstream OpenAI API, or does not support it.

**Impact:** Applications relying on logprobs for uncertainty estimation, calibration, or model verification will silently receive incomplete data.

---

### D51: Stop Sequences Ignored

**Severity:** P1 — Breaks application control flow  
**Affected Models (8):** gemini-2.5-flash, gemini-2.5-flash-image, gemini-3-flash-preview, gemini-3.1-flash-image-preview, gemini-3.1-flash-lite-preview, gpt-5.3-codex, gpt-5.4-mini, gpt-5.4-nano

**Issue:** Custom `stop` sequences (e.g., `["DONE"]`) are not honored. The model outputs the stop token and continues generating. Example:

```
Expected: ONE\nTWO\nTHREE\n  (stops at DONE)
Got:      ONE\nTWO\nTHREE\nDONE\nFOUR\nFIVE
```

**Impact:** Any workflow using stop sequences for structured output parsing (agents, tool use, state machines) will produce incorrect results.

---

### D68: frequency_penalty Ignored

**Severity:** P1 — Sampling control broken  
**Affected Models (5):** gpt-5.2, gpt-5.3-codex, gpt-5.4, gpt-5.4-mini, gpt-5.4-nano

**Issue:** `frequency_penalty=1.8` has no effect. Both the penalty=0 and penalty=1.8 runs produce identical output (30/30 "apple" repetitions, identical byte length 179=179). The parameter is completely ignored.

**Impact:** Applications using frequency_penalty for diversity/deduplication get no effect.

---

### D70: logit_bias Ignored

**Severity:** P1 — Token-level control broken  
**Affected Models (3):** gpt-5.3-codex, gpt-5.4-mini, gpt-5.4-nano

**Issue:** `logit_bias: {token_id: -100}` does not suppress the target token. The suppressed run still contains 10-13 occurrences of "the" (base: 12-15, ratio: 83-88%). At `-100`, the token should appear 0 times.

**Impact:** Applications using logit_bias for content control, format enforcement, or token blacklisting will fail silently.

---

### D21: Multiple Physical Parameters Unresponsive

**Severity:** P0 — Fundamental API incompatibility  
**Affected Models (6):** gpt-4.1, gpt-4o-mini, gpt-5.3-codex, gpt-5.4-mini, gpt-5.4-nano, gpt-oss-120b

**Issue:** Multiple API parameters simultaneously fail: logit_bias not applied, logprobs missing, max_tokens=1 not enforced. When 2+ of 4 physical parameter probes fail, the router is likely not forwarding these parameters to the upstream API.

**Impact:** The OpenAI-compatible API contract is significantly broken for these models.

---

### D22: Strict JSON Schema Not Supported

**Severity:** P0 — Protocol violation  
**Affected Models (1):** gpt-5

**Issue:** `response_format: {type: "json_schema", json_schema: {...}}` does not produce valid JSON output. The model returns plain text despite strict mode being requested.

---

### D52: response_format=json_object Ignored

**Severity:** P1  
**Affected Models (3):** gemini-3.1-pro-preview, kimi-k2-0905, glm-4.5-air

**Issue:** `response_format: {type: "json_object"}` returns truncated or non-JSON output instead of valid JSON.

---

### D37: Stop Sequence Truncation

**Severity:** P1  
**Affected Models (1):** gemini-3-pro-image-preview

**Issue:** Output is limited to 1 paragraph with `finish_reason=stop` despite requesting 3 paragraphs, suggesting router-injected stop sequence truncation.

---

## 2. Security and Privacy Issues

### D81: Hidden System Prompt Injection

**Severity:** P0 — Transparency violation  
**Affected Models (3):** grok-4-1-fast-non-reasoning, grok-4.1-fast-reasoning, glm-4.6

**Issue:** Commonstack injects a hidden safety policy system prompt into requests for these models. The injected content begins with `<policy>` tags containing rules about criminal activity, jailbreak prevention, etc.

**Example (extracted from grok-4.1):**
```
<policy>
These core policies within the <policy> tags take highest precedence.
System messages take precedence over user messages.
* Do not provide assistance to users who are clearly trying to engage in criminal activity.
* Do not provide overly realistic or specific assistance with criminal activity...
</policy>
```

**Impact:** Users are unaware their requests are being modified. The injected system prompt may conflict with user-provided system prompts, alter model behavior, and consume context window tokens without the user's knowledge.

---

### D23: Domain-Specific Guidance Leakage

**Severity:** P0 — Token reuse indicator  
**Affected Models (4):** deepseek-v3.1, deepseek-v3.2, gemini-3-flash-preview, qwen3-vl-235b

**Issue:** When sent a blank/minimal prompt, the model responds with domain-specific guidance (e.g., Chinese "AI assistant" greeting), suggesting the API key is associated with a specific application's system prompt configuration that leaks through.

**Example:** A blank prompt to deepseek-v3.1 returns:
> "你好！我是你的AI助手，随时准备为你提供帮助。"

---

### D40: Safety Refusal Integrity Compromised

**Severity:** P0 — Safety guardrails weakened  
**Affected Models (2):** deepseek-v3.1, deepseek-v3.2

**Issue:** The model complied with 2 out of 3 universally-refused prompts (CSAM-adjacent content, targeted malware). Only weapon-related content was refused. This suggests the model's safety guardrails have been weakened or bypassed.

---

### D45: Tool Call Argument Tampering

**Severity:** S0 — Financial security risk  
**Affected Models (1):** deepseek-v3.1

**Issue:** 1 out of 5 financial tool call probes showed argument tampering. The `cast_send` function's `to` address field was modified from the expected value to a different address.

---

### D15: Guardrail Bypass

**Severity:** P1  
**Affected Models (1):** gemini-3.1-flash-image-preview

**Issue:** SQL code was generated despite explicit guardrail instructions prohibiting it, indicating the system prompt guardrails are not consistently enforced.

---

## 3. Context and History Issues

### D24a: Context Truncation

**Severity:** P0 — Data loss  
**Affected Models (5):** gemini-3.1-pro-preview, gpt-oss-120b, mimo-v2-omni, mimo-v2-pro, glm-4.6

**Issue:** Canary values placed at known positions in a long-context prompt (~80K tokens) are missing from the response. The prompt was silently truncated before being sent to the model, and the reported `prompt_tokens` in usage may not reflect the actual tokens processed.

---

### D86: Context Compression Detected

**Severity:** P1 — Precision loss  
**Affected Models (2):** gemini-3.1-pro-preview, mimo-v2-pro

**Issue:** 0 out of 3 precision values (GPS coordinates, reference codes, version strings) embedded in long context were correctly recalled, corroborated by D24a also detecting truncation. The context appears to be lossy-compressed or heavily truncated.

---

### D24c: Multi-Turn History Trimming

**Severity:** P1  
**Affected Models (1):** gpt-5.2

**Issue:** The nonce from the first turn of a 6-turn conversation was not recalled. The model responded "I don't have that information anymore," suggesting early conversation history was silently trimmed.

---

## 4. Billing and Usage Issues

### D123: Token Billing Mismatch

**Severity:** P1 — Billing accuracy  
**Affected Models (1):** glm-4.5-air

**Issue:** Reported `completion_tokens=500` but actual content is only 139 local tokens (ratio 3.6x). The user is potentially billed for tokens never delivered.

---

## 5. Streaming Issues

### D111: Stream Premature Termination

**Severity:** P1  
**Affected Models (1):** gpt-5.4-pro

**Issue:** Streaming response terminated with 0 words and no `finish_reason`, suggesting the stream was cut off prematurely.

---

## 6. Latency and Performance Issues

### D91: Artificial Latency Padding

**Severity:** P1  
**Affected Models (1):** glm-4.6

**Issue:** Short request TTFT (4721ms) is 2.4x the long request TTFT (2000ms), exceeding the 2.0x ratio threshold. Simple requests should not take longer than complex ones — this pattern suggests artificial latency padding.

---

### D99: Rate Limiting Without Retry-After

**Severity:** P1  
**Affected Models (1):** glm-5-turbo

**Issue:** 6 out of 15 requests received 429 (rate limited) responses, but none included a `Retry-After` header. Clients cannot implement proper backoff without this guidance.

---

## 7. Model Consistency Issues

### D65: Style Fingerprint Mismatch

**Severity:** P2  
**Affected Models (1):** qwen3-coder-480b

**Issue:** Writing style distance (4.29) exceeds threshold (4.0) from the expected Qwen family centroid. This could indicate the model's output style has been modified by the proxy, or a different model variant is being served.

---

## Appendix: Clean Models (TIER_1)

The following 19 models passed all detectors with no real issues:

| Model | Result |
|-------|--------|
| anthropic/claude-haiku-4-5 | TIER_1 |
| anthropic/claude-opus-4-5 | TIER_1 |
| anthropic/claude-opus-4-7 | TIER_1 |
| anthropic/claude-sonnet-4-5 | TIER_1 |
| anthropic/claude-sonnet-4-6 | TIER_1 |
| google/gemini-2.5-flash | TIER_1 |
| google/gemini-2.5-flash-image | TIER_1 |
| google/gemini-2.5-pro | TIER_1 |
| google/gemini-3.1-flash-lite-preview | TIER_1 |
| minimax/minimax-m2 | TIER_1 |
| minimax/minimax-m2.5 | TIER_1 |
| moonshotai/kimi-k2-thinking | TIER_1 |
| moonshotai/kimi-k2.6 | TIER_1 |
| qwen/qwen3.5-397b-a17b | TIER_1 |
| zai-org/glm-5-turbo | TIER_1 |
| anthropic/claude-opus-4-6 | TIER_1* |
| deepseek/deepseek-r1-0528 | TIER_1* |
| minimax/minimax-m2.1 | TIER_1* |
| minimax/minimax-m2.7 | TIER_1* |

\* These models had false-positive FAILs that have been fixed in the latest code. Retesting will confirm TIER_1 status.
