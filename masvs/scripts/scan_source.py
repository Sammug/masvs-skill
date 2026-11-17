import argparse
import json
import re
import stat
import sys
from bisect import bisect_right
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import SECRET_PATTERNS, redact, walk  # noqa: E402
from detect_stack import detect  # noqa: E402

RULES_PATH = Path(__file__).resolve().parent.parent / "data" / "rules.json"
KNOWN_STACKS = frozenset({"android", "ios", "flutter", "react-native"})
MAX_BYTES = 2_000_000
SNIPPET_MAX = 200
NON_POD_DIRS = frozenset({"Target Support Files", "Headers", "Local Podspecs"})
VERSION_TAIL = re.compile(r"-\d+(?:\.\d+)+(?:[+\-][0-9A-Za-z.+\-]*)?$")
GIT_HASH_TAIL = re.compile(r"-[0-9a-f]{7,40}$")


def glob_to_regex(glob: str) -> re.Pattern:
    out, i = [], 0
    while i < len(glob):
        if glob.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
            continue
        c = glob[i]
        if glob.startswith("**", i):
            out.append(".*")
            i += 1
        elif c == "*":
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c == "{":
            j = glob.index("}", i)
            out.append("(?:" + "|".join(re.escape(a) for a in glob[i + 1:j].split(",")) + ")")
            i = j
        else:
            out.append(re.escape(c))
        i += 1
    return re.compile("".join(out) + r"\Z")


def _opt(raw: dict, key: str, flags: int = re.M):
    return re.compile(raw[key], flags) if raw.get(key) else None


class Rule:
    def __init__(self, raw: dict):
        self.raw = raw
        self.id = raw["id"]
        self.control = raw["control"]
        self.stacks = set(raw["stacks"])
        pattern = raw["pattern"]
        if pattern.startswith("@secret:"):
            pattern = SECRET_PATTERNS[pattern[len("@secret:"):]]
        self.pattern = re.compile(pattern, re.M)
        self.files = glob_to_regex(raw["files"])
        self.exclude_files = glob_to_regex(raw["exclude_files"]) if raw.get("exclude_files") else None
        self.unresolved = _opt(raw, "unresolved_pattern", 0)
        self.exclude = _opt(raw, "exclude_pattern", 0)
        self.in_file = _opt(raw, "requires_in_file")
        self.unless_in_file = _opt(raw, "unless_in_file")
        self.absent = bool(raw.get("absent"))
        self.requires = raw.get("requires")

    def applies(self, stacks: set, rel: str) -> bool:
        if "*" not in self.stacks and not self.stacks & stacks:
            return False
        if not self.files.match(rel):
            return False
        return not (self.exclude_files and self.exclude_files.match(rel))


def load_rules(path: Path = RULES_PATH) -> list:
    return [Rule(r) for r in json.loads(path.read_text())["rules"]]


def read_text(path: Path):
    try:
        st = path.stat()
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def owner_of(rel: str) -> str:
    parts = rel.split("/")
    dirs = parts[:-1]

    def at(i):
        return dirs[i] if i < len(dirs) else None

    for i in range(len(dirs) - 1, -1, -1):
        if dirs[i] == "node_modules" and at(i + 1):
            if at(i + 1).startswith("@") and at(i + 2):
                return f"{dirs[i + 1]}/{dirs[i + 2]}"
            return dirs[i + 1]
    for i, d in enumerate(dirs):
        if d == "hosted" and at(i + 2) and VERSION_TAIL.search(dirs[i + 2]):
            return VERSION_TAIL.sub("", dirs[i + 2])
        if d == ".pub-cache" and at(i + 1) == "git" and at(i + 2):
            return GIT_HASH_TAIL.sub("", dirs[i + 2])
        if d == "Pods":
            name = at(i + 1)
            return name if name and name not in NON_POD_DIRS and not name.endswith(".xcodeproj") else "Pods"
        if d == "files-2.1" and at(i + 2):
            return dirs[i + 2]
    return "app"


def make_snippet(line: str, col: int) -> str:
    lead = len(line) - len(line.lstrip())
    body = line.strip()
    out = redact(body)
    if len(out) > SNIPPET_MAX:
        start = max(0, len(redact(body[:max(col - lead, 0)])) - 80)
        out = redact(out[start:start + SNIPPET_MAX])
    return out[:SNIPPET_MAX]


class LockCache:
    def __init__(self, root: Path):
        self.root = root
        self._versions: dict[Path, dict] = {}

    def nearest(self, start: Path, name: str):
        d = start
        while True:
            if (d / name).is_file():
                return d / name
            if d == self.root or d.parent == d:
                return None
            d = d.parent

    def majors(self, lock: Path) -> dict:
        if lock not in self._versions:
            self._versions[lock] = _parse_pubspec_lock(read_text(lock) or "")
        return self._versions[lock]


def _parse_pubspec_lock(text: str) -> dict:
    out, current = {}, None
    for line in text.splitlines():
        m = re.match(r"^  ([A-Za-z0-9_]+):\s*$", line)
        if m:
            current = m.group(1)
            continue
        v = re.match(r'^    version:\s*"?(\d+)\.', line)
        if v and current:
            out[current] = int(v.group(1))
    return out


def check_requires(rule: Rule, path: Path, locks: LockCache):
    req = rule.requires
    if req["lock"] != "pubspec.lock":
        return "skip", f"unsupported lockfile {req['lock']}"
    lock = locks.nearest(path.parent, req["lock"])
    if lock is None:
        return "skip", f"{req['lock']} not found"
    major = locks.majors(lock).get(req["package"])
    if major is None or major > req["max_major"]:
        return "no", None
    return "ok", None


def scan(root, stacks=None, include_deps: bool = False) -> dict:
    root = Path(root)
    if stacks is None:
        stacks = detect(root)["stacks"]
    stack_set = set(stacks)
    rules = [r for r in load_rules() if "*" in r.stacks or r.stacks & stack_set]
    locks = LockCache(root)
    matches, seen, skipped = [], set(), {}

    for path in walk(root, include_deps):
        rel = path.relative_to(root).as_posix()
        candidates = [r for r in rules if r.applies(stack_set, rel)]
        if not candidates:
            continue
        text = read_text(path)
        if text is None:
            continue
        starts = [0] + [m.end() for m in re.finditer("\n", text)]
        owner = owner_of(rel)

        def line_at(offset: int):
            n = bisect_right(starts, offset)
            end = starts[n] if n < len(starts) else len(text)
            return n, text[starts[n - 1]:end].rstrip("\r\n"), offset - starts[n - 1]

        def emit(rule: Rule, offset: int):
            n, line, col = line_at(offset)
            key = (rule.id, rel, n)
            if key in seen:
                return
            seen.add(key)
            status = "unresolved" if rule.unresolved and rule.unresolved.search(line) else "match"
            matches.append({
                "rule": rule.id, "control": rule.control, "file": rel, "line": n,
                "snippet": make_snippet(line, col), "owner": owner, "status": status,
            })

        for r in candidates:
            if r.in_file and not r.in_file.search(text):
                continue
            if r.unless_in_file and r.unless_in_file.search(text):
                continue
            if r.absent:
                if r.pattern.search(text):
                    continue
                anchor = r.in_file.search(text) if r.in_file else None
                emit(r, anchor.start() if anchor else 0)
                continue
            for m in r.pattern.finditer(text):
                if r.exclude and r.exclude.search(line_at(m.start())[1]):
                    continue
                if r.requires:
                    verdict, reason = check_requires(r, path, locks)
                    if verdict == "skip":
                        skipped.setdefault(r.id, reason)
                        break
                    if verdict == "no":
                        break
                emit(r, m.start())

    matches.sort(key=lambda m: (m["file"], m["line"], m["rule"]))
    return {
        "stacks": sorted(stack_set),
        "matches": matches,
        "skipped_rules": [{"rule": k, "reason": v} for k, v in sorted(skipped.items())],
    }


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        print(json.dumps({"error": message}))
        sys.exit(2)


def main(argv: list[str]) -> int:
    ap = _Parser(prog="scan_source.py")
    ap.add_argument("root")
    ap.add_argument("--stacks")
    ap.add_argument("--include-deps", action="store_true")
    args = ap.parse_args(argv[1:])
    root = Path(args.root)
    if not root.is_dir():
        print(json.dumps({"error": f"not a directory: {args.root}"}))
        return 2
    stacks = None
    if args.stacks is not None:
        stacks = [s.strip() for s in args.stacks.split(",") if s.strip()]
        bad = sorted(set(stacks) - KNOWN_STACKS)
        if bad:
            print(json.dumps({"error": f"unknown stack: {', '.join(bad)}"}))
            return 2
    print(json.dumps(scan(root, stacks, args.include_deps), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
