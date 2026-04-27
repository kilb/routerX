// 85 check items for an LLM router endpoint diagnostic.
// Organized into 8 categories. Each item has: id, category, title, desc, expected.

window.CHECK_CATEGORIES = [
  { id: 'CON', name: 'Connectivity',      label: 'Connectivity & Transport' },
  { id: 'AUT', name: 'Authentication',    label: 'Authentication & Identity' },
  { id: 'SCH', name: 'Schema',            label: 'OpenAI Schema Conformance' },
  { id: 'GEN', name: 'Generation',        label: 'Generation Quality' },
  { id: 'STR', name: 'Streaming',         label: 'Streaming & Events' },
  { id: 'TOL', name: 'Tool Use',          label: 'Tool / Function Calling' },
  { id: 'CTX', name: 'Context',           label: 'Context Window & Memory' },
  { id: 'PRF', name: 'Performance',       label: 'Performance & Reliability' },
];

window.CHECKS = [
  // Connectivity (1-11)
  { cat:'CON', title:'TLS handshake',            desc:'Negotiates TLS 1.2+ without downgrade' },
  { cat:'CON', title:'Certificate chain valid',  desc:'Root CA trusted, no self-signed leaf' },
  { cat:'CON', title:'HTTP/2 support',           desc:'Upgrades from HTTP/1.1 cleanly' },
  { cat:'CON', title:'DNS resolves under 50ms',  desc:'Hostname resolves from measurement region' },
  { cat:'CON', title:'Round-trip < 400ms',       desc:'Baseline RTT to endpoint origin' },
  { cat:'CON', title:'OPTIONS preflight',        desc:'CORS preflight returns 200 / 204' },
  { cat:'CON', title:'gzip / br accepted',       desc:'Accepts compressed response encodings' },
  { cat:'CON', title:'Keep-alive honored',       desc:'Connection reused across serial requests' },
  { cat:'CON', title:'IPv6 reachable',           desc:'AAAA record serves equivalent route' },
  { cat:'CON', title:'Status 405 on wrong verb', desc:'GET to /chat/completions returns 405' },
  { cat:'CON', title:'Content-type negotiated',  desc:'application/json accepted + returned' },

  // Authentication (12-21)
  { cat:'AUT', title:'Bearer token accepted',    desc:'Authorization: Bearer <key> authorizes' },
  { cat:'AUT', title:'Missing key → 401',        desc:'No auth returns canonical 401' },
  { cat:'AUT', title:'Invalid key → 401',        desc:'Bad token returns 401, not 500' },
  { cat:'AUT', title:'Key not echoed in body',   desc:'Secret never reflected in response' },
  { cat:'AUT', title:'Key not echoed in errors', desc:'Secret scrubbed from error traces' },
  { cat:'AUT', title:'Org header respected',     desc:'OpenAI-Organization routes correctly' },
  { cat:'AUT', title:'Scoped permission honored',desc:'Read-only key blocks completions' },
  { cat:'AUT', title:'Rate-limit headers set',   desc:'x-ratelimit-* headers present' },
  { cat:'AUT', title:'Request-ID returned',      desc:'x-request-id uniquely identifies call' },
  { cat:'AUT', title:'Clock skew tolerance',     desc:'±60s skew accepted on signed requests' },

  // Schema (22-32)
  { cat:'SCH', title:'POST /v1/chat/completions',desc:'Endpoint exists at canonical path' },
  { cat:'SCH', title:'Response has id',          desc:'Top-level id string present' },
  { cat:'SCH', title:'Response has object',      desc:'object = "chat.completion"' },
  { cat:'SCH', title:'Response has created',     desc:'Unix timestamp within ±5s of now' },
  { cat:'SCH', title:'choices[0].message.role',  desc:'Equals "assistant"' },
  { cat:'SCH', title:'choices[0].finish_reason', desc:'One of stop | length | tool_calls' },
  { cat:'SCH', title:'usage.prompt_tokens',      desc:'Integer ≥ 1, matches tokenizer' },
  { cat:'SCH', title:'usage.completion_tokens',  desc:'Integer ≥ 0, matches output' },
  { cat:'SCH', title:'usage.total_tokens',       desc:'Equals prompt + completion' },
  { cat:'SCH', title:'Model field echoed',       desc:'Response model matches requested' },
  { cat:'SCH', title:'System fingerprint stable',desc:'Same value across identical calls' },

  // Generation (33-44)
  { cat:'GEN', title:'Single-turn completion',   desc:'"Hello" → non-empty reply' },
  { cat:'GEN', title:'Multi-turn coherence',     desc:'Tracks assistant turns in history' },
  { cat:'GEN', title:'System prompt honored',    desc:'Persona instruction followed' },
  { cat:'GEN', title:'Temperature=0 deterministic', desc:'Same seed → same tokens' },
  { cat:'GEN', title:'Temperature=1.5 varies',   desc:'High temp produces diverse outputs' },
  { cat:'GEN', title:'top_p clipping',           desc:'top_p=0.1 narrows distribution' },
  { cat:'GEN', title:'max_tokens respected',     desc:'Output truncated to limit' },
  { cat:'GEN', title:'stop sequences honored',   desc:'Generation halts at stop token' },
  { cat:'GEN', title:'Unicode round-trip',       desc:'Emoji + CJK preserved verbatim' },
  { cat:'GEN', title:'Markdown preserved',       desc:'Code fences / tables survive encoding' },
  { cat:'GEN', title:'JSON mode valid',          desc:'response_format=json_object parses' },
  { cat:'GEN', title:'JSON schema adherence',    desc:'Structured output matches schema' },

  // Streaming (45-55)
  { cat:'STR', title:'stream=true opens SSE',    desc:'Content-Type text/event-stream' },
  { cat:'STR', title:'First chunk < 2s',         desc:'Time-to-first-token under budget' },
  { cat:'STR', title:'Chunks are valid JSON',    desc:'Each data: line parses' },
  { cat:'STR', title:'Delta role on first',      desc:'choices[0].delta.role = assistant' },
  { cat:'STR', title:'Content deltas continuous',desc:'Concatenation reconstructs message' },
  { cat:'STR', title:'[DONE] sentinel sent',     desc:'Stream terminates with "data: [DONE]"' },
  { cat:'STR', title:'finish_reason on last',    desc:'Final non-DONE chunk carries reason' },
  { cat:'STR', title:'Usage in final chunk',     desc:'stream_options include_usage works' },
  { cat:'STR', title:'Abort closes socket',      desc:'Client abort frees server resources' },
  { cat:'STR', title:'No buffering stall',       desc:'Chunk cadence < 500ms gaps' },
  { cat:'STR', title:'Heartbeat comments',       desc:': keep-alive emitted when idle' },

  // Tool Use (56-66)
  { cat:'TOL', title:'tools[] accepted',         desc:'Schema passes validation' },
  { cat:'TOL', title:'tool_choice=auto',         desc:'Model decides when to call' },
  { cat:'TOL', title:'tool_choice=required',     desc:'Forces tool invocation' },
  { cat:'TOL', title:'Named tool_choice',        desc:'Forces a specific function name' },
  { cat:'TOL', title:'Arguments are JSON',       desc:'function.arguments parses cleanly' },
  { cat:'TOL', title:'Arguments match schema',   desc:'Validates against parameters.jsonSchema' },
  { cat:'TOL', title:'Parallel tool calls',      desc:'Multiple tools in one turn' },
  { cat:'TOL', title:'Tool result ingestion',    desc:'role=tool messages accepted back' },
  { cat:'TOL', title:'Streaming tool args',      desc:'Incremental arg deltas over SSE' },
  { cat:'TOL', title:'finish_reason=tool_calls', desc:'Correctly signaled on tool turn' },
  { cat:'TOL', title:'Unknown tool rejected',    desc:'Graceful error, not hallucinated call' },

  // Context (67-77)
  { cat:'CTX', title:'2k context',               desc:'Handles 2,048-token prompt' },
  { cat:'CTX', title:'8k context',               desc:'Handles 8,192-token prompt' },
  { cat:'CTX', title:'32k context',              desc:'Handles 32,768-token prompt' },
  { cat:'CTX', title:'128k context',             desc:'Handles 128k-token prompt' },
  { cat:'CTX', title:'Overflow → 400',           desc:'Rejects >max with clean error' },
  { cat:'CTX', title:'Needle-in-haystack (near)',desc:'Recalls fact at 10% depth' },
  { cat:'CTX', title:'Needle-in-haystack (mid)', desc:'Recalls fact at 50% depth' },
  { cat:'CTX', title:'Needle-in-haystack (far)', desc:'Recalls fact at 90% depth' },
  { cat:'CTX', title:'Truncation semantics',     desc:'truncation=auto drops oldest' },
  { cat:'CTX', title:'System prompt preserved',  desc:'System survives context compression' },
  { cat:'CTX', title:'Token counter accuracy',   desc:'Reported tokens within ±2% of tokenizer' },

  // Performance (78-85)
  { cat:'PRF', title:'p50 latency',              desc:'Median completion < 1.5s on small prompt' },
  { cat:'PRF', title:'p95 latency',              desc:'95th percentile < 4s on small prompt' },
  { cat:'PRF', title:'Tokens/sec output',        desc:'Sustained > 40 tok/s on streaming' },
  { cat:'PRF', title:'Concurrency = 10',         desc:'10 parallel requests all succeed' },
  { cat:'PRF', title:'Concurrency = 50',         desc:'50 parallel requests, <1% errors' },
  { cat:'PRF', title:'429 backoff honored',      desc:'Retry-After respected, no hammering' },
  { cat:'PRF', title:'5xx retry safe',           desc:'Idempotent retries succeed' },
  { cat:'PRF', title:'Cold vs warm delta',       desc:'Cold-start penalty < 2× warm' },
];

// Sanity: we should have exactly 85.
console.assert(window.CHECKS.length === 85, 'expected 85 checks, got ' + window.CHECKS.length);
