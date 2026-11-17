from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Iterator

IGNORE_DIRS: frozenset[str] = frozenset(
    {"build", ".dart_tool", "node_modules", "Pods", ".gradle", "DerivedData", ".git", "vendor"}
)
DEP_DIRS: frozenset[str] = frozenset({"node_modules", "Pods", "vendor", ".pub-cache"})


def walk(root: Path, include_deps: bool = False) -> Iterator[Path]:
    pruned = IGNORE_DIRS - DEP_DIRS if include_deps else IGNORE_DIRS | DEP_DIRS
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in pruned)
        for name in sorted(filenames):
            yield Path(dirpath) / name


SECRET_PATTERNS: dict[str, str] = {
    "aws_access_key": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
    "gitlab_pat": r"\bglpat-[0-9A-Za-z_\-]{20,}",
    "github_token": r"\b(?:gh[pousr]_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{22,})",
    "google_api_key": r"\bAIza[0-9A-Za-z_\-]{35}",
    "slack_token": r"\bxox[bp]-[0-9A-Za-z\-]{10,}",
    "private_key": (
        r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY(?: BLOCK)?-----"
        r'(?:[^\n"]*?-----END[^-\n]*-----)?[^\n"]*'
    ),
    "stripe_live_key": r"\b[rs]k_live_[0-9A-Za-z]{16,}",
    "sk_api_key": r"\bsk-[0-9A-Za-z_\-]{20,}",
    "jwt": r"\beyJ[0-9A-Za-z_\-]{8,}\.[0-9A-Za-z_\-]{8,}\.[0-9A-Za-z_\-]{8,}",
}
_SECRET_RE = re.compile("|".join(f"(?:{p})" for p in SECRET_PATTERNS.values()))


def redact(text: str) -> str:
    return _SECRET_RE.sub(lambda m: m.group(0)[:4] + "\u2026", text)


_LITERAL_RE = re.compile(
    r"""(?P<q>['"])(?=[A-Za-z0-9_\-+/=.]{16,}(?P=q))(?=[^'"]*\d)(?=[^'"]*[A-Za-z])"""
    r"""(?P<v>[A-Za-z0-9_\-+/=.]{16,})(?P=q)"""
)


def redact_literals(text: str) -> str:
    return _LITERAL_RE.sub(lambda m: m.group("q") + m.group("v")[:4] + "\u2026" + m.group("q"), text)
