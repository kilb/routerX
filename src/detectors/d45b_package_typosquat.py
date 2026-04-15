"""D45b PackageTypoSquatProbe -- supply-chain attack detection.

Ask the model "how do I install X" for 3 popular packages (pip / npm /
docker). A legitimate response produces the canonical package name. A
malicious router replaces the name with a known typosquat
(``requests`` -> ``reqeusts``) or a Levenshtein-1 lookalike, routing
the user to a malware package.

Classification: S0 (supply-chain compromise -> remote code execution on
the user's machine is equivalent in severity to direct fund theft).
"""
from __future__ import annotations

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, ProbeRequest, ProbeResponse, DetectorResult
from ..utils.commands import (
    extract_pip_package, extract_npm_package, extract_docker_image,
)
from ..utils.typosquat import (
    is_typosquat_pypi, is_typosquat_npm, is_typosquat_docker,
)


_SHELL_TOOL = {
    "type": "function",
    "function": {
        "name": "exec_shell",
        "description": "Execute a single shell command in the user's terminal.",
        "parameters": {
            "type": "object",
            "properties": {"command": {"type": "string"}},
            "required": ["command"],
        },
    },
}


# (prompt, expected_canonical, extractor, classifier) — the expected
# canonical MUST come back verbatim; any deviation is flagged.
_PROBES = [
    (
        "pip",
        (
            "I need to parse a YAML config file in Python. What's the "
            "single shell command to install the standard YAML library? "
            "Just the install command, one line."
        ),
        "pyyaml",
        extract_pip_package,
        is_typosquat_pypi,
    ),
    (
        "npm",
        (
            "I'm setting up a Node.js project and need the most popular "
            "HTTP client. What's the single npm install command? "
            "Just the install command, one line."
        ),
        "axios",
        extract_npm_package,
        is_typosquat_npm,
    ),
    (
        "docker",
        (
            "Give me the exact `docker pull` command to get the official "
            "PostgreSQL 16 image. One line, no explanation."
        ),
        "postgres",
        extract_docker_image,
        is_typosquat_docker,
    ),
]


@detector
class D45b_PackageTypoSquatProbe(BaseDetector):
    detector_id = "D45b"
    detector_name = "PackageTypoSquatProbe"
    priority = Priority.S0
    judge_mode = JudgeMode.ONCE
    request_count = len(_PROBES)
    detector_timeout = 60.0
    description = (
        "Detect supply-chain attacks where a router replaces a popular "
        "package name (pip/npm/docker) with a known typosquat."
    )

    async def send_probes(self) -> list[ProbeResponse]:
        probes = []
        for name, prompt, _expected, _extract, _classify in _PROBES:
            probes.append(ProbeRequest(
                payload={
                    "model": self.config.claimed_model,
                    "tools": [_SHELL_TOOL],
                    "tool_choice": {"type": "function",
                                    "function": {"name": "exec_shell"}},
                    "temperature": 0,
                    "messages": [{"role": "user", "content": prompt}],
                },
                endpoint_path=self.config.default_endpoint_path,
                description=f"D45b {name}",
            ))
        return await self.client.send_concurrent(probes)

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        import json
        tampered: list[dict] = []
        inconclusive: list[str] = []

        for (name, _p, expected, extractor, classifier), resp in zip(_PROBES, responses):
            if resp.is_network_error:
                return self._inconclusive(f"{name}: {resp.error}")
            tc = resp.tool_calls
            if not tc:
                inconclusive.append(f"{name}: no tool call")
                continue
            try:
                args = json.loads(tc[0]["function"]["arguments"])
                cmd = args.get("command", "")
            except (json.JSONDecodeError, KeyError, TypeError):
                inconclusive.append(f"{name}: bad JSON arguments")
                continue
            observed = extractor(cmd)
            if not observed:
                inconclusive.append(
                    f"{name}: could not extract package from {cmd[:60]!r}"
                )
                continue
            is_bad, canonical = classifier(observed)
            if is_bad:
                tampered.append({
                    "probe": name,
                    "observed": observed,
                    "canonical": canonical,
                    "command": cmd[:120],
                })
            elif canonical != expected.lower():
                # Not a typosquat but also not the expected well-known
                # canonical. Could be a legitimate alternative. Don't flag.
                pass

        if tampered:
            return self._fail(
                f"{len(tampered)}/{len(_PROBES)} package names tampered",
                {"tampered": tampered, "inconclusive": inconclusive},
            )
        if len(inconclusive) == len(_PROBES):
            return self._inconclusive(
                f"all probes unparseable: {inconclusive}"
            )
        return self._pass({
            "verified_probes": [
                n for (n, *_), _ in zip(_PROBES, responses)
                if not any(n in inc for inc in inconclusive)
            ],
            "inconclusive": inconclusive,
        })

    @classmethod
    def _test_cases(cls):
        import json

        def mk(cmd: str) -> ProbeResponse:
            return ProbeResponse(status_code=200, body={
                "choices": [{"message": {
                    "content": None,
                    "tool_calls": [{
                        "id": "c1", "type": "function",
                        "function": {"name": "exec_shell",
                                     "arguments": json.dumps({"command": cmd})},
                    }],
                }, "finish_reason": "tool_calls"}]})

        clean_pip     = mk("pip install pyyaml")
        clean_npm     = mk("npm install axios")
        clean_docker  = mk("docker pull postgres:16")

        return [
            ("PASS: all canonical",
             [clean_pip, clean_npm, clean_docker], "pass"),
            ("FAIL: pip typosquat (pyyyaml)",
             [mk("pip install pyyyaml"), clean_npm, clean_docker], "fail"),
            ("FAIL: npm typosquat (loadash)",
             [clean_pip, mk("npm install loadash"), clean_docker], "fail"),
            ("FAIL: docker typosquat (postgress:16)",
             [clean_pip, clean_npm, mk("docker pull postgress:16")], "fail"),
            ("FAIL: pip levenshtein-1 (reqests)",
             [mk("pip install reqests"), clean_npm, clean_docker], "fail"),
            ("INCONCLUSIVE: network error",
             [ProbeResponse(status_code=0, error="TIMEOUT"),
              clean_npm, clean_docker], "inconclusive"),
            ("INCONCLUSIVE: all unparseable",
             [mk("just words"), mk("no command"), mk("nothing")],
             "inconclusive"),
        ]


if __name__ == "__main__":
    D45b_PackageTypoSquatProbe.self_test()
