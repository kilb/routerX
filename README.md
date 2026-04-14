# Router Auditor

**Admission test suite for LLM API routers.** Detects dishonest behavior in LLM-proxy gateways (model substitution, parameter tampering, financial fraud, supply-chain attacks, multimodal degradation, web-reverse-proxy impersonation) via 33 targeted detectors.

```
+-------------------+     +--------------+     +-----------+
|  TestRunner       | --> |  31 Detectors | --> |  Report   |
|  (5 stages)       |     |  (probe+judge)|     |  (JSON +  |
|                   |     |               |     |   JUnit)  |
+-------------------+     +--------------+     +-----------+
```

## Install

```bash
python -m venv .venv
.venv/bin/pip install -e .[serve]   # includes granian + uvicorn
# Or just dev tools:
.venv/bin/pip install -e .[dev]
```

Supported Python: **3.11+**

## Quick start

### 1. Run CLI against a real router

```bash
.venv/bin/python -m scripts.admission_test \
  --endpoint https://router.example.com/v1 \
  --api-key sk-xxx \
  --model gpt-4o \
  --output report.json \
  --junit-xml junit.xml
```

Exit codes: `0` = clean (TIER_1 / TIER_1_WATCH / TIER_2); `1` = **BLACKLIST**; `2` = bad `--only` IDs.

### 2. Run as an HTTP API

```bash
AUDITOR_API_KEY=secret-123 .venv/bin/python -m scripts.serve --port 8900
```

```bash
# Create a test
curl -X POST http://localhost:8900/api/v1/tests \
  -H "Authorization: Bearer secret-123" \
  -H "Content-Type: application/json" \
  -d '{"router_endpoint":"https://router.example.com/v1","api_key":"sk-xxx"}'
# -> {"task_id":"abc123def456", "ws_url":"/api/v1/tests/abc123def456/ws"}

# Poll status
curl -H "Authorization: Bearer secret-123" \
  http://localhost:8900/api/v1/tests/abc123def456

# Stream progress via WebSocket at ws_url
```

### 3. Run against a mock router (for CI)

```bash
# Terminal 1
.venv/bin/uvicorn tests.mock_server:app --port 8999

# Terminal 2
.venv/bin/python -m scripts.admission_test \
  --endpoint http://127.0.0.1:8999/v1 \
  --api-key test \
  --only D25 D28
```

## Tier interpretation

| Tier | Meaning | Trigger |
|------|---------|---------|
| **BLACKLIST** | Permanently reject router | Any S0 or P0 FAIL |
| **TIER_2** | Degraded quality — watch | Any P1 FAIL |
| **TIER_1_WATCH** | Passed but one detector was SUSPICIOUS (MAJORITY 1/2) | Any SUSPICIOUS verdict |
| **TIER_1** | Clean admission | All PASS |

## Detector categories

33 detectors across 5 stages:

- **PRE_SCREEN (1)** — `D31 GodPayload`: composite 5-check early warning
- **S0 (6)** — Irreversible damage: D28 session crosstalk, D47 address tampering, D48 amount tampering, D45 wallet tool-call tampering (EVM/Uniswap/BTC/Solana/Stripe), D45b package typosquat (pip/npm/docker), D45c installer URL redirection (curl | sh / git clone / kubectl apply) -> BLACKLIST
- **P0 (9)** — Severe violations: D21 physical-param blindspot, D22/D22e protocol strictness, D23 hijacked API key, D30 error-path forensics, D50 semantic negation, D4a tokenizer fingerprint, D4b negative constraint, D16b tool-calling -> BLACKLIST
- **P1 (13)** — Quality violations: D24a/b context truncation, D25 output cap, D26 semantic cache, D27/b/c/d multimodal fidelity, D29 billing fraud, D32a streaming, D38 seed, D54 task completion, D55 async task -> TIER_2
- **P2 (4)** — General warnings: D11 request integrity, D15 guardrail, D37 stop-sequence, D53 metadata -> logged

See `docs/00_overview.md` through `docs/04_p2_warning.md` for per-detector specs.

## Config options

| Flag | Description |
|------|-------------|
| `--endpoint` | Router base URL (e.g. `https://foo/v1`) |
| `--api-key` | Router API key |
| `--model` | Claimed model alias (default `gpt-4o`) |
| `--provider` | `openai` / `anthropic` / `gemini` / `any` |
| `--single-route` | Declare router claims single-provider routing (enables D22e) |
| `--capabilities` | `text`, `vision`, `pdf`, `audio`, `task_model` |
| `--auth-method` | `bearer` (default) / `x-api-key` / `query` |
| `--api-format` | `openai` / `anthropic` / `auto` |
| `--direct-endpoint` + `--direct-api-key` | Optional direct-provider baseline for D48/D50/D53 |
| `--only D25 D28` | Restrict to specific detectors |
| `--timeout` | Per-request timeout seconds (default 30) |

## Development

### Run all tests

```bash
AUDITOR_API_KEY=test .venv/bin/python -m pytest tests/
# 19 tests pass: 11 API + 8 mock-driven integration
```

### Batch self-test all 31 detectors (offline, mocked)

```bash
.venv/bin/python -m scripts.self_test_all
# 31/31 detectors pass self-test
```

### Add a new detector

1. Create `src/detectors/dXX_your_name.py` (file name must start with `d{num}`)
2. Inherit `BaseDetector`, declare class vars. See `CLAUDE.md` for the full template and style guide.
3. Run `.venv/bin/python -m src.detectors.dXX_your_name` to verify
4. `@detector` auto-registers; `src.detectors.__init__` auto-scans

## Architecture

```
src/
├── models.py           Pydantic data models
├── client.py           Async httpx client with rate limiting + retries
├── runner.py           5-stage orchestrator + contradiction detection
├── registry.py         BaseDetector + @detector + MAJORITY lifecycle
├── tokenizer.py        tiktoken wrapper
├── assets.py           Probe generators (images/PDF/audio)
├── config.py           Fingerprint constants
├── events.py           EventBus for progress
├── reporter.py         CLI + JUnit XML
├── utils/              nonce, eth, text_analysis, timing
├── detectors/          31 detector files (auto-scanned)
└── api/                FastAPI HTTP layer

scripts/                CLI entries
tests/                  pytest suite + behavioral mock server
```

## Security notes

- API auth uses `hmac.compare_digest` (constant-time)
- `extra_headers` values masked as `***` in GET /tests/{id}
- `api_key` / `direct_api_key` always excluded from JSON responses
- CORS is `*` — suitable for internal networks; add reverse proxy for external exposure
- Single-key auth — no multi-tenant isolation

## License

MIT (see `LICENSE`).
