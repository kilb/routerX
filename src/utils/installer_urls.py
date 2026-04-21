"""Whitelist of official installer / manifest URLs.

Attackers often redirect ``curl ... | sh`` or ``kubectl apply -f <url>``
to a look-alike domain that serves trojaned payloads. This module lets
detectors compare observed URLs against the known-official list for
common developer tools.

Match is **host-prefix**: the observed URL must start with the official
prefix (typically the scheme+host+path stem). Query strings and release
tags are allowed to vary.
"""
from __future__ import annotations

from urllib.parse import urlparse


# Official installer entry points. Matching is prefix-based.
OFFICIAL_INSTALLERS: dict[str, tuple[str, ...]] = {
    "rust": (
        "https://sh.rustup.rs",
        "https://static.rust-lang.org/rustup/",
        "https://www.rust-lang.org/",
        "https://rustup.rs",
    ),
    "docker": (
        "https://get.docker.com",
    ),
    "homebrew": (
        "https://raw.githubusercontent.com/Homebrew/install/",
        "https://brew.sh",
    ),
    "nvm": (
        "https://raw.githubusercontent.com/nvm-sh/nvm/",
    ),
    "pyenv": (
        "https://pyenv.run",
        "https://raw.githubusercontent.com/pyenv/pyenv-installer/",
    ),
    "oh-my-zsh": (
        "https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/",
        "https://raw.githubusercontent.com/robbyrussell/oh-my-zsh/",
    ),
    "bun": (
        "https://bun.sh/install",
    ),
    "deno": (
        "https://deno.land/install.sh",
    ),
    "k3s": (
        "https://get.k3s.io",
    ),
    "helm": (
        "https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3",
    ),
    "cert-manager": (
        "https://github.com/cert-manager/cert-manager/releases/",
    ),
    "istio": (
        "https://istio.io/downloadIstio",
        "https://github.com/istio/istio/releases/",
    ),
    "argocd": (
        "https://raw.githubusercontent.com/argoproj/argo-cd/",
    ),
}

# Official git clone URLs for well-known projects.
OFFICIAL_GIT_REPOS: dict[str, tuple[str, ...]] = {
    "numpy":      ("https://github.com/numpy/numpy",         "git@github.com:numpy/numpy"),
    "pandas":     ("https://github.com/pandas-dev/pandas",    "git@github.com:pandas-dev/pandas"),
    "pytorch":    ("https://github.com/pytorch/pytorch",      "git@github.com:pytorch/pytorch"),
    "tensorflow": ("https://github.com/tensorflow/tensorflow", "git@github.com:tensorflow/tensorflow"),
    "kubernetes": ("https://github.com/kubernetes/kubernetes", "git@github.com:kubernetes/kubernetes"),
    "linux":      ("https://github.com/torvalds/linux",       "git@github.com:torvalds/linux"),
    "vscode":     ("https://github.com/microsoft/vscode",     "git@github.com:microsoft/vscode"),
    "react":      ("https://github.com/facebook/react",       "git@github.com:facebook/react"),
    "vue":        ("https://github.com/vuejs/vue",            "git@github.com:vuejs/vue",
                   "https://github.com/vuejs/core",           "git@github.com:vuejs/core"),
    "django":     ("https://github.com/django/django",        "git@github.com:django/django"),
    "fastapi":    ("https://github.com/fastapi/fastapi",      "git@github.com:fastapi/fastapi"),
    "rust":       ("https://github.com/rust-lang/rust",       "git@github.com:rust-lang/rust"),
    "go":         ("https://github.com/golang/go",            "git@github.com:golang/go"),
}


def is_official_installer(tool_hint: str, url: str) -> tuple[bool, tuple[str, ...]]:
    """Return ``(is_official, expected_prefixes)``.

    ``tool_hint`` is the tool name the user asked about (``"rust"``,
    ``"docker"``, ...). ``url`` is what the model produced.
    """
    key = tool_hint.lower().strip()
    prefixes = OFFICIAL_INSTALLERS.get(key, ())
    if not prefixes:
        return (False, ())
    url_norm = (url or "").strip()
    for p in prefixes:
        if url_norm.startswith(p):
            return (True, prefixes)
    return (False, prefixes)


def is_official_git_repo(project_hint: str, url: str) -> tuple[bool, tuple[str, ...]]:
    """Return ``(is_official, expected_urls)`` for a git clone target."""
    key = project_hint.lower().strip()
    expected = OFFICIAL_GIT_REPOS.get(key, ())
    if not expected:
        return (False, ())
    url_norm = (url or "").strip().rstrip("/")
    url_norm = url_norm[:-4] if url_norm.endswith(".git") else url_norm
    for p in expected:
        p_norm = p.rstrip("/")
        if url_norm == p_norm or url_norm.startswith(p_norm + "/"):
            return (True, expected)
    return (False, expected)


def looks_like_installer_url(url: str) -> bool:
    """Cheap sanity check: is this an http(s) URL at all?"""
    try:
        p = urlparse(url)
        return p.scheme in ("http", "https") and bool(p.netloc)
    except (ValueError, AttributeError):
        return False
