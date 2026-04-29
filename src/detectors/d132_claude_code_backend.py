"""D132 ClaudeCodeBackendDetection -- detect Claude Code as unauthorized backend.

Claude Code (Anthropic's CLI) injects a distinctive system prompt and
registers ~15 tools (Read, Write, Bash, Grep, Glob, Edit, etc.).  When
someone reverse-proxies Claude Code Max, these artifacts leak:

  1. **Tool inventory**: asking the model to list tools reveals Claude Code's
     toolset (Read, Write, Bash, Grep, Glob, Edit, Agent, etc.)
  2. **Command execution**: the model can actually execute shell commands,
     which a normal API cannot do.
  3. **System prompt leakage**: the model may reference its "working directory",
     "git repository", or "CLI" context.

Sends two probes and scores the number of Claude Code fingerprints found.
"""
from __future__ import annotations

import re

from ..registry import detector, BaseDetector
from ..models import (
    DetectorResult,
    JudgeMode,
    Priority,
    ProbeRequest,
    ProbeResponse,
)

# Claude Code's distinctive tool names. Generic words like "read" and "write"
# appear in normal text, so we use two tiers:
# - Specific tools (grep, glob, todowrite, etc.) that never appear generically
# - A regex pattern that matches the capitalized "Tool" naming convention
#   (e.g. "Read tool", "Bash -", "Glob —") used in Claude Code's tool listing
_SPECIFIC_TOOLS = {
    "grep", "glob", "todowrite", "todoupdate", "todoread",
    "webfetch", "websearch", "notebookedit",
}
# Pattern: tool name as a titled/capitalized word followed by tool-list
# indicators (dash, colon, parenthesis, "tool")
_TOOL_LIST_RE = re.compile(
    r"\b(Read|Write|Edit|Bash|Grep|Glob|Agent|WebFetch|WebSearch|TodoWrite)"
    r"\s*(?:[-—:\(]|tool\b)",
    re.IGNORECASE,
)

# Phrases that only appear in Claude Code's system prompt context
_CONTEXT_PHRASES = [
    "working directory",
    "git repository",
    "claude code",
    "cli tool",
    "current working directory",
    "codebase",
    "tool use",
    "file_path",
    "bash command",
    "read tool",
    "write tool",
    "edit tool",
    "glob tool",
    "grep tool",
]

# Strong signals: the model claims it can execute commands or read files
_EXECUTION_PHRASES = [
    r"i (?:can|am able to|have access to) (?:run|execute) (?:bash |shell )?commands?",
    r"i (?:can|am able to) read (?:and write )?files",
    r"i have (?:access to|the following) tools?",
    r"available tools?:?\s*\n",
    r"(?:Read|Write|Edit|Bash|Grep|Glob)\s*(?:tool|—|:|\()",
]
_EXECUTION_RE = re.compile("|".join(_EXECUTION_PHRASES), re.IGNORECASE)

_TOOL_MIN_MATCHES = 4
_CONTEXT_MIN_MATCHES = 2


@detector
class D132_ClaudeCodeBackendDetection(BaseDetector):
    detector_id = "D132"
    detector_name = "ClaudeCodeBackendDetection"
    priority = Priority.S0
    judge_mode = JudgeMode.MAJORITY_2_OF_2
    request_count = 2
    detector_timeout = 30.0
    description = (
        "Detect Claude Code as unauthorized backend by probing for its "
        "distinctive tool inventory and execution capabilities."
    )

    async def send_probes(self) -> list[ProbeResponse]:
        ep = self.config.default_endpoint_path
        model = self.config.claimed_model

        # Probe 1: ask for tool inventory
        tool_probe = ProbeRequest(
            payload={
                "model": model,
                "max_tokens": 300,
                "temperature": 0,
                "messages": [{"role": "user", "content": (
                    "List every tool, function, or capability you have access to. "
                    "Be specific and exhaustive. Format as a numbered list."
                )}],
            },
            endpoint_path=ep,
            description="D132 tool inventory probe",
        )

        # Probe 2: ask about working context
        context_probe = ProbeRequest(
            payload={
                "model": model,
                "max_tokens": 200,
                "temperature": 0,
                "messages": [{"role": "user", "content": (
                    "What is your current working directory? "
                    "What files can you see? Describe your environment."
                )}],
            },
            endpoint_path=ep,
            description="D132 environment probe",
        )

        return [
            await self.client.send(tool_probe),
            await self.client.send(context_probe),
        ]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r_tool, r_ctx = responses[0], responses[1]
        signals: list[str] = []
        ev: dict = {}

        # --- Probe 1: Tool inventory ---
        if r_tool.is_network_error or r_tool.status_code != 200:
            ev["tool_probe"] = "failed"
        else:
            content_lower = (r_tool.content or "").lower()
            content_raw = r_tool.content or ""
            # Tier 1: specific tool names that never appear generically
            specific_hits = [t for t in _SPECIFIC_TOOLS if t in content_lower]
            # Tier 2: capitalized tool names in list format ("Read tool", "Bash -")
            list_hits = _TOOL_LIST_RE.findall(content_raw)
            matched_tools = list(set(specific_hits + [h.lower() for h in list_hits]))
            ev["matched_tools"] = matched_tools
            ev["tool_count"] = len(matched_tools)
            if len(matched_tools) >= _TOOL_MIN_MATCHES:
                signals.append("tool_inventory")

            # Check for execution claim phrases
            if _EXECUTION_RE.search(r_tool.content or ""):
                signals.append("execution_claim")
                ev["execution_claim"] = True

        # --- Probe 2: Environment context ---
        if r_ctx.is_network_error or r_ctx.status_code != 200:
            ev["context_probe"] = "failed"
        else:
            content = (r_ctx.content or "").lower()
            matched_phrases = [
                p for p in _CONTEXT_PHRASES if p in content
            ]
            ev["matched_context"] = matched_phrases
            ev["context_count"] = len(matched_phrases)
            if len(matched_phrases) >= _CONTEXT_MIN_MATCHES:
                signals.append("environment_context")

            # Strong signal: model reports an actual directory path
            if re.search(r"(?:/home/|/usr/|/var/|/tmp/|C:\\)", content):
                signals.append("real_path")
                ev["real_path"] = True

        ev["signals"] = signals

        # Tool inventory alone is a strong signal (4+ Claude Code tool names)
        if "tool_inventory" in signals:
            return self._fail(
                f"Claude Code backend detected: model lists {ev.get('tool_count', 0)} "
                f"Claude Code tools ({', '.join(ev.get('matched_tools', [])[:5])})",
                ev,
            )
        # Environment context + execution claim
        if "environment_context" in signals and "execution_claim" in signals:
            return self._fail(
                "Claude Code backend detected: model claims execution "
                "capabilities and references working environment",
                ev,
            )
        # Real filesystem path is a very strong standalone signal
        if "real_path" in signals:
            return self._fail(
                "Claude Code backend detected: model reports real filesystem path",
                ev,
            )

        return self._pass(ev)

    @classmethod
    def _test_cases(cls):
        def mk(content: str) -> ProbeResponse:
            return ProbeResponse(
                status_code=200,
                body={"choices": [{"message": {"content": content},
                                   "finish_reason": "stop"}]},
            )

        # Normal API: generic capabilities
        normal_tool = mk(
            "I'm a language model. I can:\n"
            "1. Answer questions\n"
            "2. Write text\n"
            "3. Analyze data\n"
            "4. Help with coding"
        )
        normal_ctx = mk(
            "I don't have access to a filesystem or working directory. "
            "I'm a language model that processes text."
        )

        # Claude Code backend: lists specific tools
        cc_tool = mk(
            "I have access to the following tools:\n"
            "1. Read - read files from the filesystem\n"
            "2. Write - write files to the filesystem\n"
            "3. Edit - edit existing files\n"
            "4. Bash - execute shell commands\n"
            "5. Grep - search file contents\n"
            "6. Glob - find files by pattern\n"
            "7. Agent - spawn sub-agents"
        )
        cc_ctx = mk(
            "My current working directory is /home/user/project. "
            "This is a git repository with the following files..."
        )

        # Edge case: model mentions "read" and "write" generically
        generic_rw = mk(
            "I can read and write text. I can also edit documents "
            "and help with bash scripting questions."
        )
        generic_ctx = mk(
            "I don't have a working directory. I'm an AI assistant."
        )

        return [
            ("PASS: normal API response",
             [normal_tool, normal_ctx], "pass"),
            ("FAIL: Claude Code tool inventory",
             [cc_tool, cc_ctx], "fail"),
            ("PASS: generic read/write mentions (below threshold)",
             [generic_rw, generic_ctx], "pass"),
            ("PASS: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT"),
              normal_ctx], "pass"),
        ]


if __name__ == "__main__":
    D132_ClaudeCodeBackendDetection.self_test()
