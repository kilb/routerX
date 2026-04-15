"""Constants and fingerprint libraries shared across detectors.

These values are static reference data. Detectors that need per-model
fingerprints (D4a) MUST generate them at runtime via ``token_counter`` --
the tables below are only fallbacks for comparison.
"""
from __future__ import annotations

# logit_bias candidate tokens (D21b).
LOGIT_BIAS_CANDIDATES: list[str] = [" the", " a", " is", " to", " of", " and"]

# Pre-computed tokenizer fingerprints (D4a).
# D4a MUST also generate the ground-truth tokenization at runtime using
# tiktoken for the claimed model; these strings are only fallback references.
TOKENIZER_FINGERPRINTS: dict[str, dict[str, list[str]]] = {
    "SolidGoldMagikarp": {
        "openai_cl100k": ["Solid", "Gold", "Mag", "ik", "arp"],
        "openai_o200k": ["Solid", "Gold", "Mag", "ikarp"],
    },
    "sjkldfjsldkfj": {
        "openai_cl100k": ["sj", "kl", "df", "js", "ld", "kf", "j"],
        "openai_o200k": ["sjk", "ldf", "jsld", "kfj"],
    },
    " petertodd": {
        "openai_cl100k": [" peter", "todd"],
        "openai_o200k": [" peter", "todd"],
    },
}

# D4a test strings (do not modify -- carefully chosen for fingerprinting).
TOKENIZER_PROBE_STRINGS: list[str] = [
    "SolidGoldMagikarp",  # GPT-family glitch token
    "sjkldfjsldkfj",      # nonsense -- high inter-tokenizer variance
    " petertodd",         # leading space + name -- sensitive to boundaries
]

# Provider parameter limits (D22d / D30a).
PROVIDER_PARAM_LIMITS: dict[str, dict[str, float]] = {
    "openai": {"temperature_max": 2.0},
    "anthropic": {"temperature_max": 1.0},
    "gemini": {"temperature_max": 2.0},
}

# Known fake-error fingerprints (D30). Lower-cased substring match.
KNOWN_FAKE_PATTERNS: list[str] = [
    "new_api_error", "one_api_error", "<html", "<!doctype",
    "cloudflare", "ray id", "captcha_required", "poe daily limit",
    "usage quota exceeded",
]

# Keywords typical of hijacked 3rd-party API keys (D23).
# CJK entries use \u escapes so the source stays ASCII-only while still
# matching responses that render literal Chinese characters.
HIJACKED_KEYWORDS: list[str] = [
    "cursor", "monica", "translate", "translation",
    "homework", "code assistant", "copilot",
    "\u7ffb\u8bd1",   # fan-yi (translate)
    "\u4f5c\u4e1a",   # zuo-ye (homework)
]

# Standard provider response headers (D30).
KNOWN_PROVIDER_HEADERS: set[str] = {
    "x-request-id", "x-ratelimit-limit-requests", "cf-ray",
}
