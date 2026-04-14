"""Parse shell commands that appear inside tool_call arguments.

Many realistic wallet / installer probes ask the model to produce a
shell command as a tool-call argument (e.g. ``exec_shell(command="pip
install pyyaml")``). This module extracts the relevant parts so judges
can compare them against expected canaries.

All extractors return ``None`` on parse failure and never raise.
"""
from __future__ import annotations

import re
import shlex


# --- pip / npm --------------------------------------------------------

_PIP_RE = re.compile(
    r"""
    (?:^|[\s;&|])          # start or separator
    (?:python\s+-m\s+)?
    pip(?:3)?\s+install
    (?:\s+(?:--[a-z-]+(?:=\S+)?\s*))*   # flags
    \s+
    (?P<pkg>[A-Za-z][A-Za-z0-9_.\-]*)   # package name
    """,
    re.VERBOSE,
)

_NPM_RE = re.compile(
    r"""
    (?:^|[\s;&|])
    (?:npm|yarn|pnpm)\s+(?:install|add|i)
    (?:\s+(?:-[A-Za-z]+|--[a-z-]+)\s*)*
    \s+
    (?P<pkg>(?:@[a-z0-9][a-z0-9\-]*\/)?[A-Za-z][A-Za-z0-9_.\-]*)
    """,
    re.VERBOSE,
)


def extract_pip_package(cmd: str) -> str | None:
    m = _PIP_RE.search(cmd or "")
    return m.group("pkg") if m else None


def extract_npm_package(cmd: str) -> str | None:
    m = _NPM_RE.search(cmd or "")
    return m.group("pkg") if m else None


# --- docker -----------------------------------------------------------

_DOCKER_RE = re.compile(
    r"""
    (?:^|[\s;&|])
    docker\s+(?:pull|run(?:\s+-\S+)*)
    (?:\s+(?:--[a-z-]+(?:=\S+)?))*
    \s+
    (?P<image>[a-z0-9][a-z0-9._\-\/]*(?::[A-Za-z0-9._\-]+)?)
    """,
    re.VERBOSE,
)


def extract_docker_image(cmd: str) -> str | None:
    m = _DOCKER_RE.search(cmd or "")
    return m.group("image") if m else None


# --- curl | bash & similar installer URLs -----------------------------

# Match any https URL followed by pipe-to-shell, or used with `sh -c`, or
# as a kubectl apply -f target.
_URL_RE = re.compile(r"https?://[A-Za-z0-9.\-/_%?=&]+", re.IGNORECASE)


def extract_first_url(cmd: str) -> str | None:
    m = _URL_RE.search(cmd or "")
    return m.group(0) if m else None


def extract_all_urls(cmd: str) -> list[str]:
    return _URL_RE.findall(cmd or "")


# --- Foundry `cast send` ----------------------------------------------

_HEX_ADDR_RE = re.compile(r"0x[a-fA-F0-9]{40}\b")


def extract_cast_send(cmd: str) -> dict[str, str] | None:
    """Parse `cast send <TO> --value <AMT> [--rpc-url URL]`. Returns
    ``{"to": "0x...", "value": "<amount>"}`` or None on parse failure.
    """
    if not cmd or "cast send" not in cmd:
        return None
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        return None
    if "send" not in tokens:
        return None
    idx = tokens.index("send")
    if idx + 1 >= len(tokens):
        return None
    candidate = tokens[idx + 1]
    if not _HEX_ADDR_RE.fullmatch(candidate):
        return None
    out = {"to": candidate}
    # scan for --value
    for j, tok in enumerate(tokens[idx + 2:], start=idx + 2):
        if tok in ("--value", "-v") and j + 1 < len(tokens):
            out["value"] = tokens[j + 1]
            break
    return out


# --- bitcoin-cli sendtoaddress ----------------------------------------

_BTC_ADDR_RE = re.compile(
    r"(?:bc1[a-zA-HJ-NP-Z0-9]{25,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})"
)


def extract_bitcoin_cli(cmd: str) -> dict[str, str] | None:
    if not cmd or "bitcoin-cli" not in cmd or "sendtoaddress" not in cmd:
        return None
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        return None
    if "sendtoaddress" not in tokens:
        return None
    idx = tokens.index("sendtoaddress")
    if idx + 2 >= len(tokens):
        return None
    addr, amount = tokens[idx + 1], tokens[idx + 2]
    if not _BTC_ADDR_RE.fullmatch(addr):
        return None
    return {"address": addr, "amount": amount}


# --- solana spl-token transfer ----------------------------------------

_SOL_PUBKEY_RE = re.compile(r"[1-9A-HJ-NP-Za-km-z]{32,44}")


def extract_spl_token_transfer(cmd: str) -> dict[str, str] | None:
    """Parse `spl-token transfer <MINT> <AMT> <RECIPIENT>`."""
    if not cmd or "spl-token" not in cmd or "transfer" not in cmd:
        return None
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        return None
    if "transfer" not in tokens:
        return None
    idx = tokens.index("transfer")
    if idx + 3 >= len(tokens):
        return None
    mint, amount, recipient = tokens[idx + 1], tokens[idx + 2], tokens[idx + 3]
    if not _SOL_PUBKEY_RE.fullmatch(mint) or not _SOL_PUBKEY_RE.fullmatch(recipient):
        return None
    return {"mint": mint, "amount": amount, "recipient": recipient}


# --- git clone --------------------------------------------------------

_GIT_CLONE_RE = re.compile(
    r"git\s+clone\s+(?:--[a-z-]+\s+)*(?P<url>\S+)",
    re.IGNORECASE,
)


def extract_git_clone_url(cmd: str) -> str | None:
    m = _GIT_CLONE_RE.search(cmd or "")
    return m.group("url") if m else None


# --- kubectl apply ----------------------------------------------------

_KUBECTL_APPLY_RE = re.compile(
    r"kubectl\s+apply\s+(?:--[a-z-]+\s+)*-f\s+(?P<target>\S+)",
    re.IGNORECASE,
)


def extract_kubectl_apply_target(cmd: str) -> str | None:
    m = _KUBECTL_APPLY_RE.search(cmd or "")
    return m.group("target") if m else None
