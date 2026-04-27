/* global: React, CHECKS, CHECK_CATEGORIES */

// ————————————— utilities —————————————
const pad = (n, w = 3) => String(n).padStart(w, '0');
const fmtMs = (ms) => ms == null ? '—' : (ms >= 1000 ? (ms/1000).toFixed(2) + 's' : Math.round(ms) + 'ms');
const nowStamp = () => {
  const d = new Date();
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}.${p(d.getMonth()+1)}.${p(d.getDate())} · ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
};
const sessionId = () => 'SX-' + Math.random().toString(36).slice(2, 8).toUpperCase() + '-' + Math.random().toString(36).slice(2, 6).toUpperCase();

// Pseudo-random but stable per checkId
function seeded(id, salt = 0) {
  let h = 2166136261 ^ salt;
  for (let i = 0; i < id.length; i++) {
    h = Math.imul(h ^ id.charCodeAt(i), 16777619);
  }
  return ((h >>> 0) % 10000) / 10000;
}

// synthesize plausible result: status + latency + payloads
function synthResult(check, idx) {
  const id = check.cat + '-' + pad(idx);
  const r = seeded(id);
  const r2 = seeded(id, 7);

  // ~86% pass, 9% warn, 5% fail, distributed by category tendency
  let status;
  if (r < 0.86) status = 'pass';
  else if (r < 0.95) status = 'warn';
  else status = 'fail';

  // hard-pin a few to make the report feel real
  const forcedFails = ['STR-045','CTX-070','PRF-083','AUT-018'];
  const forcedWarns = ['GEN-037','TOL-059','PRF-085','CON-004'];
  if (forcedFails.includes(id)) status = 'fail';
  if (forcedWarns.includes(id)) status = 'warn';

  // latency 30–2400ms, performance checks slower
  const base = check.cat === 'PRF' ? 800 : check.cat === 'CTX' ? 600 : check.cat === 'STR' ? 420 : 140;
  const latency = Math.round(base + r2 * base * 2.5 + r * 140);

  // synthesize request/response payloads
  const req = buildRequestSample(check, id);
  const resp = buildResponseSample(check, id, status);
  const note = buildNote(check, status);

  return { id, status, latency, req, resp, note };
}

function buildRequestSample(check, id) {
  if (check.cat === 'CON' || check.cat === 'AUT') {
    return `GET /v1/models HTTP/2\nHost: <endpoint>\nAuthorization: Bearer sk-**** (redacted)\nAccept: application/json\nUser-Agent: router-diag/1.4 (${id})`;
  }
  if (check.cat === 'STR') {
    return `POST /v1/chat/completions\n{\n  "model": "<model>",\n  "stream": true,\n  "messages": [{"role":"user","content":"ping"}],\n  "stream_options": { "include_usage": true }\n}`;
  }
  if (check.cat === 'TOL') {
    return `POST /v1/chat/completions\n{\n  "model": "<model>",\n  "messages": [{"role":"user","content":"What's the weather in Osaka?"}],\n  "tools": [{\n    "type":"function",\n    "function":{\n      "name":"get_weather",\n      "parameters":{"type":"object","properties":{"city":{"type":"string"}}}\n    }\n  }],\n  "tool_choice": "auto"\n}`;
  }
  if (check.cat === 'CTX') {
    return `POST /v1/chat/completions\n{\n  "model": "<model>",\n  "messages": [ ...padding (${check.title.match(/\d+/)?.[0] || 'N'}k tokens)...,\n    {"role":"user","content":"Recall the secret word embedded above."}\n  ]\n}`;
  }
  if (check.cat === 'GEN' || check.cat === 'SCH') {
    return `POST /v1/chat/completions\n{\n  "model": "<model>",\n  "messages": [{"role":"user","content":"Say hello in one short sentence."}],\n  "temperature": 0.0,\n  "max_tokens": 32\n}`;
  }
  return `POST /v1/chat/completions\n{ "model": "<model>", ... }`;
}

function buildResponseSample(check, id, status) {
  if (status === 'fail') {
    if (check.cat === 'STR') {
      return `HTTP/2 200 OK\ncontent-type: application/json\n\n{\n  "choices": [ { "message": { "role":"assistant", "content":"..." } } ]\n}\n\n// expected: text/event-stream — server collapsed to full JSON body.\n// TTFB 3.8s (budget 2.0s).`;
    }
    if (check.cat === 'AUT') {
      return `HTTP/2 401 Unauthorized\nwww-authenticate: Bearer realm="api"\n\n{\n  "error": { "code": "invalid_api_key", "type": "auth", "message": "API key not recognized." }\n}\n\n// expected: read-only scope to reject chat.completions; received 200 with completion.`;
    }
    if (check.cat === 'PRF') {
      return `// 50 parallel requests: 46 ok, 3 × 502, 1 × socket-closed\n// error rate 8.0% (threshold 1.0%)\n// p95 under load: 7.4s (budget 4.0s)`;
    }
    if (check.cat === 'CTX') {
      return `{\n  "choices":[{"message":{"content":"I don't see that information in the provided context."}}],\n  "usage":{"prompt_tokens":9824,"completion_tokens":18}\n}\n\n// needle placed at depth 0.50 not recovered; recall = 0/5 probes`;
    }
    return `// assertion failed — see note below`;
  }
  if (status === 'warn') {
    if (check.cat === 'GEN') {
      return `{\n  "choices":[{"message":{"content":"Hello there."},"finish_reason":"stop"}],\n  "usage":{"prompt_tokens":14,"completion_tokens":3,"total_tokens":17}\n}\n\n// determinism: 4/5 runs identical, 1 run diverged at token 2.`;
    }
    if (check.cat === 'PRF') {
      return `// 10 parallel requests succeeded\n// p95 warm→cold ratio 2.18× (soft limit 2.0×)`;
    }
    return `// passed with caveats — see note.`;
  }
  // pass
  return `HTTP/2 200 OK\ncontent-type: application/json\nx-request-id: req_${id.toLowerCase()}_${Math.random().toString(36).slice(2,10)}\n\n{\n  "id": "chatcmpl_${Math.random().toString(36).slice(2,14)}",\n  "object": "chat.completion",\n  "model": "<model>",\n  "choices": [ {\n    "index": 0,\n    "message": { "role":"assistant","content":"Hello." },\n    "finish_reason": "stop"\n  } ],\n  "usage": { "prompt_tokens": 14, "completion_tokens": 1, "total_tokens": 15 }\n}`;
}

function buildNote(check, status) {
  const S = check.title;
  if (status === 'fail') {
    const msgs = {
      CON:`Network path acceptable but \`${S}\` did not meet spec. Recheck router egress config.`,
      AUT:`\`${S}\` returned a non-canonical error. Verify auth middleware and scope enforcement.`,
      SCH:`Schema drift detected on \`${S}\`. Non-OpenAI-compatible field or missing key.`,
      GEN:`\`${S}\` produced unexpected content. Determinism or control parameter may be ignored.`,
      STR:`Streaming contract broken on \`${S}\`. Most SDKs will hang or silently fall back.`,
      TOL:`Tool-call surface does not honor \`${S}\`. Agent frameworks will misroute.`,
      CTX:`Context handling on \`${S}\` is truncating or forgetting. Retrieval tasks at risk.`,
      PRF:`Performance budget exceeded on \`${S}\`. Consider queuing, caching, or region.`,
    };
    return msgs[check.cat] || `\`${S}\` failed.`;
  }
  if (status === 'warn') {
    return `\`${S}\` passed within tolerance but showed intermittent variance. Monitor across a longer window.`;
  }
  return `\`${S}\` satisfied expectation across all probes.`;
}

// ————————————— presets —————————————
const PRESETS = [
  { name: 'OpenAI',     endpoint: 'https://api.openai.com/v1', model: 'gpt-4o-mini' },
  { name: 'Anthropic',  endpoint: 'https://api.anthropic.com/v1', model: 'claude-haiku-4-5' },
  { name: 'DeepSeek',   endpoint: 'https://api.deepseek.com/v1', model: 'deepseek-chat' },
  { name: 'Groq',       endpoint: 'https://api.groq.com/openai/v1', model: 'llama-3.3-70b-versatile' },
  { name: 'OpenRouter', endpoint: 'https://openrouter.ai/api/v1', model: 'anthropic/claude-sonnet-4' },
  { name: 'Local',      endpoint: 'http://localhost:8080/v1', model: 'custom' },
];

Object.assign(window, {
  pad, fmtMs, nowStamp, sessionId,
  synthResult, PRESETS,
});
