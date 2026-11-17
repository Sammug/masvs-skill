from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import walk  # noqa: E402

DEP_NAMES = {
    "pubspec.yaml", "pubspec.lock", "package.json", "package-lock.json",
    "yarn.lock", "pnpm-lock.yaml", "build.gradle", "build.gradle.kts",
    "Podfile", "Podfile.lock",
}
GRADLE_NAMES = {"build.gradle", "build.gradle.kts"}
ANDROID_PLUGIN = re.compile(r"com\.android\.|apply\s+plugin:\s*['\"]android|id\s*\(?\s*['\"]android")
FLUTTER_KEY = re.compile(r"^flutter:|sdk:\s*flutter", re.M)


def read(path: Path) -> str:
    try:
        return path.read_text(errors="replace")
    except OSError:
        return ""


def is_rn(path: Path) -> bool:
    try:
        data = json.loads(read(path))
    except ValueError:
        return False
    if not isinstance(data, dict):
        return False
    for key in ("dependencies", "devDependencies"):
        deps = data.get(key)
        if isinstance(deps, dict) and "react-native" in deps:
            return True
    return False


def detect(root: Path) -> dict:
    root = Path(root)
    stacks: set[str] = set()
    manifests: list[str] = []
    plists: list[str] = []
    deps: list[str] = []

    def rel(p: Path) -> str:
        return p.relative_to(root).as_posix()

    for p in walk(root):
        name = p.name
        if name in DEP_NAMES:
            deps.append(rel(p))
        if name == "pubspec.yaml" and FLUTTER_KEY.search(read(p)):
            stacks.add("flutter")
            _add_native_dirs(p.parent, stacks)
        elif name == "package.json" and is_rn(p):
            stacks.add("react-native")
            _add_native_dirs(p.parent, stacks)
        elif name == "AndroidManifest.xml":
            manifests.append(rel(p))
            stacks.add("android")
        elif name in GRADLE_NAMES and ANDROID_PLUGIN.search(read(p)):
            stacks.add("android")
        elif name == "Info.plist":
            plists.append(rel(p))
            stacks.add("ios")
        if any(part.endswith(".xcodeproj") for part in p.relative_to(root).parts[:-1]):
            stacks.add("ios")

    return {
        "stacks": sorted(stacks),
        "android_manifests": sorted(manifests),
        "ios_plists": sorted(plists),
        "dependency_files": sorted(deps),
    }


def _add_native_dirs(project: Path, stacks: set[str]) -> None:
    if (project / "android").is_dir():
        stacks.add("android")
    if (project / "ios").is_dir():
        stacks.add("ios")


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[1] in ("-h", "--help"):
        print("usage: detect_stack.py <root>")
        return 0
    if len(argv) != 2:
        print(json.dumps({"error": "usage: detect_stack.py <root>"}))
        return 2
    root = Path(argv[1])
    if not root.is_dir():
        print(json.dumps({"error": f"not a directory: {argv[1]}"}))
        return 2
    print(json.dumps(detect(root), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
