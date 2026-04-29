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

# Claude Code's distinctive tool names.
# Only names that are UNIQUE to Claude Code — "grep" and "bash" are common
# shell commands so they don't count. We require PascalCase or exact compound
# names that never appear in normal conversation.
_SPECIFIC_TOOLS = {
    "todowrite", "todoupdate", "todoread", "taskcreate", "taskupdate",
    "webfetch", "websearch", "notebookedit",
    "schedulewakeup", "exitplanmode", "enterplanmode",
}
# Claude Code lists tools in a distinctive format with PascalCase names.
# Only match compound PascalCase names (WebFetch, TodoWrite, NotebookEdit)
# that cannot appear in normal text. Skip simple words like Read/Write/Bash.
_TOOL_LIST_RE = re.compile(
    r"\b(WebFetch|WebSearch|TodoWrite|TodoUpdate|TodoRead|TaskCreate|"
    r"TaskUpdate|NotebookEdit|ScheduleWakeup|EnterPlanMode|ExitPlanMode|"
    r"ExitWorktree|EnterWorktree|ReadMcpResourceTool|ListMcpResourcesTool)"
    r"\b",
)

# Phrases unique to Claude Code's system prompt — generic dev terms removed.
# Each phrase must be specific enough to not appear in a normal coding Q&A.
_CONTEXT_PHRASES = [
    "claude code",
    "claude.ai/code",
    "anthropic's official cli",
    "current working directory is /",
    "is a git repository: true",
    "primary working directory:",
    "gitStatus:",
    "auto memory",
    "memory system at",
    "CLAUDE.md",
]

# The model explicitly claims to have Claude Code's tool capabilities.
_EXECUTION_PHRASES = [
    r"i (?:can|am able to) (?:run|execute) (?:bash |shell )?commands? (?:on|in) (?:your|the) (?:system|machine|environment)",
    r"i have access to (?:tools like |the following tools:?\s*\n\s*[-\d])",
    r"(?:WebFetch|TodoWrite|NotebookEdit|TaskCreate)\s*(?:[-—:\(]|tool\b)",
]
_EXECUTION_RE = re.compile("|".join(_EXECUTION_PHRASES), re.IGNORECASE)

_TOOL_MIN_MATCHES = 3
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

            # Strong signal: model claims a specific path as its OWN working
            # directory (not just mentioning paths in a tutorial context).
            # Pattern: "my/current/working directory is /home/..." or
            # "I am in /home/..." — first-person possessive + path.
            if re.search(
                r"(?:my |current |the )?"
                r"(?:working directory|cwd|workspace|project)"
                r"[^.]{0,30}"
                r"(?:/home/|/root/|/opt/|C:\\Users\\)",
                content,
            ):
                signals.append("real_path")
                ev["real_path"] = True

        ev["signals"] = signals

        # Tool inventory alone is a strong signal (3+ Claude Code-specific
        # PascalCase tool names like WebFetch, TodoWrite, NotebookEdit)
        if "tool_inventory" in signals:
            return self._fail(
                f"Claude Code backend detected: model lists {ev.get('tool_count', 0)} "
                f"Claude Code tools ({', '.join(ev.get('matched_tools', [])[:5])})",
                ev,
            )
        # Environment context (Claude Code-specific phrases) + any other signal
        if "environment_context" in signals and len(signals) >= 2:
            return self._fail(
                "Claude Code backend detected: model references Claude Code "
                "system context + additional signals",
                ev,
            )
        # Real path alone is not enough (models discuss paths in tutorials).
        # Require at least one other supporting signal.
        if "real_path" in signals and len(signals) >= 2:
            return self._fail(
                "Claude Code backend detected: model reports real working "
                "directory path with supporting signals",
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

        # Claude Code backend: lists PascalCase tools unique to Claude Code
        cc_tool = mk(
            "I have access to the following tools:\n"
            "1. Read - read files from the filesystem\n"
            "2. Write - write files to the filesystem\n"
            "3. WebFetch - fetch web pages\n"
            "4. WebSearch - search the web\n"
            "5. TodoWrite - create todo items\n"
            "6. NotebookEdit - edit Jupyter notebooks\n"
            "7. TaskCreate - create tasks"
        )
        cc_ctx = mk(
            "My current working directory is /home/user/project. "
            "As noted in CLAUDE.md, this is a git repository."
        )

        # Edge case: model mentions grep/bash in a tutorial context
        tutorial = mk(
            "Use grep to search files, bash to run scripts, and "
            "read the file with cat. The glob pattern *.py matches "
            "Python files."
        )
        tutorial_ctx = mk(
            "To check your working directory, run pwd. "
            "Files are typically at /home/user or /usr/local."
        )

        # Edge case: model with function calling lists its own tools
        fc_model = mk(
            "I have access to the following tools:\n"
            "1. get_weather - get current weather\n"
            "2. search_web - search the internet\n"
            "3. send_email - send an email"
        )

        return [
            ("PASS: normal API response",
             [normal_tool, normal_ctx], "pass"),
            ("FAIL: Claude Code tool inventory",
             [cc_tool, cc_ctx], "fail"),
            ("PASS: tutorial mentions of grep/bash/glob (not CC tools)",
             [tutorial, tutorial_ctx], "pass"),
            ("PASS: function-calling model lists own tools",
             [fc_model, normal_ctx], "pass"),
            ("PASS: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT"),
              normal_ctx], "pass"),
        ]


if __name__ == "__main__":
    D132_ClaudeCodeBackendDetection.self_test()
