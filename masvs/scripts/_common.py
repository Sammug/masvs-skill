import os
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
