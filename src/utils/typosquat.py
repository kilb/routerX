"""Typosquat detection for pip / npm / docker package names.

Approach: curated whitelist of top packages + known-attack typosquat
lookup table + Levenshtein-1 fuzzy match against the whitelist for
unknown names. Returns ``(is_suspicious, canonical_if_known)``.

This is defensive — if a package is not on the whitelist and not a
1-edit away from any whitelisted name, we do NOT flag it (avoids false
positives on obscure-but-legitimate packages).
"""
from __future__ import annotations


# Top 50 most-downloaded PyPI packages (approximate 2024 ordering).
# These are the highest-value attack targets — a typosquat of any of
# these nets thousands of installs per day on error.
LEGITIMATE_PYPI: frozenset[str] = frozenset({
    "boto3", "urllib3", "requests", "setuptools", "pyyaml", "numpy",
    "pandas", "scipy", "six", "python-dateutil", "s3transfer", "packaging",
    "idna", "certifi", "charset-normalizer", "cryptography", "typing-extensions",
    "click", "jinja2", "markupsafe", "werkzeug", "pytz", "flask", "django",
    "fastapi", "pydantic", "starlette", "sqlalchemy", "psycopg2", "pillow",
    "matplotlib", "scikit-learn", "tensorflow", "torch", "transformers",
    "openai", "anthropic", "httpx", "aiohttp", "websockets", "redis",
    "celery", "beautifulsoup4", "lxml", "selenium", "pytest", "black",
    "ruff", "mypy", "isort", "flake8", "tqdm", "rich",
})

LEGITIMATE_NPM: frozenset[str] = frozenset({
    "lodash", "axios", "react", "react-dom", "vue", "express", "typescript",
    "next", "webpack", "babel", "jest", "eslint", "prettier", "chalk",
    "commander", "debug", "dotenv", "fs-extra", "glob", "mocha", "moment",
    "node-fetch", "nodemon", "pg", "redux", "rollup", "socket.io", "uuid",
    "ws", "yargs", "bcrypt", "jsonwebtoken", "mongoose", "cors",
    "body-parser", "@types/node", "@types/react",
})

LEGITIMATE_DOCKER: frozenset[str] = frozenset({
    "nginx", "postgres", "mysql", "redis", "mongo", "mariadb", "node",
    "python", "ubuntu", "alpine", "busybox", "debian", "centos", "fedora",
    "ruby", "golang", "rust", "openjdk", "php", "nextcloud", "wordpress",
    "httpd", "tomcat", "memcached", "rabbitmq", "elasticsearch", "traefik",
    "caddy", "hashicorp/vault", "hashicorp/consul", "prom/prometheus",
    "grafana/grafana",
})

# Known typosquat -> canonical mapping. These are real package names that
# have historically been used as malware-carrying typosquats on PyPI/npm.
KNOWN_TYPOSQUATS: dict[str, str] = {
    # PyPI historical (removed) — see PyPI typosquat research
    "pyyamls":      "pyyaml",
    "pyyyaml":      "pyyaml",
    "reqeusts":     "requests",
    "reqests":      "requests",
    "rerquests":    "requests",
    "urlib3":       "urllib3",
    "urlllib3":     "urllib3",
    "beautifulsupe": "beautifulsoup4",
    "beautifulsoup-py3": "beautifulsoup4",
    "dateutil":     "python-dateutil",  # ambiguous but often typosquat
    "tensorflow-gpu-2": "tensorflow",
    "setup-tools":  "setuptools",
    # npm historical
    "loadash":      "lodash",
    "lodahs":       "lodash",
    "axioss":       "axios",
    "axois":        "axios",
    "reactt":       "react",
    "raect":        "react",
    "reactdom":     "react-dom",
    "reaact":       "react",
    "expres":       "express",
    "expresss":     "express",
    # Docker image typosquats
    "postgress":    "postgres",
    "postgre":      "postgres",
    "ngnix":        "nginx",
    "nginxx":       "nginx",
    "myssql":       "mysql",
    "mysq":         "mysql",
    "redis-server": "redis",
    "mongod":       "mongo",
}


def _levenshtein(a: str, b: str) -> int:
    """Standard Levenshtein distance. O(|a|*|b|)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(
                min(cur[-1] + 1, prev[j] + 1, prev[j - 1] + (0 if ca == cb else 1))
            )
        prev = cur
    return prev[-1]


def _normalize(pkg: str) -> str:
    return pkg.strip().lower().replace("_", "-")


def is_typosquat(
    pkg: str, legitimate: frozenset[str],
) -> tuple[bool, str | None]:
    """Return ``(is_suspicious, canonical_if_known)``.

    - Whitelisted name → ``(False, name)``
    - Known typosquat → ``(True, canonical)``
    - Levenshtein-1 from a whitelisted name AND length > 3 → ``(True, closest)``
    - Unknown → ``(False, None)`` (do not flag)
    """
    if not pkg:
        return (False, None)
    norm = _normalize(pkg)
    if norm in legitimate:
        return (False, norm)
    if norm in KNOWN_TYPOSQUATS:
        return (True, KNOWN_TYPOSQUATS[norm])
    # Fuzzy match: distance 1 from whitelist, only for names longer than
    # 3 chars (prevents false positives on short names like "ws", "pg").
    if len(norm) > 3:
        for legit in legitimate:
            if abs(len(norm) - len(legit)) <= 1 and _levenshtein(norm, legit) == 1:
                return (True, legit)
    return (False, None)


def is_typosquat_pypi(pkg: str) -> tuple[bool, str | None]:
    return is_typosquat(pkg, LEGITIMATE_PYPI)


def is_typosquat_npm(pkg: str) -> tuple[bool, str | None]:
    return is_typosquat(pkg, LEGITIMATE_NPM)


def is_typosquat_docker(image: str) -> tuple[bool, str | None]:
    """Docker images may have `:tag` suffix and `namespace/` prefix.
    Strip to base name before checking.
    """
    if not image:
        return (False, None)
    base = image.split(":", 1)[0]
    # Keep namespace/image format intact for whitelist match
    return is_typosquat(base, LEGITIMATE_DOCKER)
