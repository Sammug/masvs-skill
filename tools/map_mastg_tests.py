#!/usr/bin/env python3
"""Rewrite mastg_tests in controls.json from a clone of github.com/OWASP/mastg.

Usage: map_mastg_tests.py <mastg_clone>
A v2 test's frontmatter lists `maswe: [MASWE-xxxx, ...]`; a control gets every
test that shares at least one MASWE id with it. Deprecated tests are skipped.
"""
import json
import re
import sys
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "skills" / "masvs" / "data" / "controls.json"


def frontmatter(path):
    text = path.read_text(encoding="utf-8")
    m = re.match(r"---\n(.*?)\n---\n", text, re.S)
    return m.group(1) if m else ""


def read_tests(clone):
    tests = {}
    for path in sorted(Path(clone).glob("tests*/**/MASTG-TEST-*.md")):
        fm = frontmatter(path)
        m = re.search(r"^maswe:\s*\[(.*?)\]", fm, re.M)
        if not m or re.search(r"^status:\s*deprecated", fm, re.M):
            continue
        tests[path.stem] = set(re.findall(r"MASWE-\d{4}", m.group(1)))
    return tests


def main(clone):
    tests = read_tests(clone)
    controls = json.loads(DATA.read_text())
    for c in controls:
        c["mastg_tests"] = sorted(t for t, w in tests.items() if w & set(c["maswe"]))
    DATA.write_text(json.dumps(controls, indent=2) + "\n")
    print(f"{len(tests)} v2 tests mapped; non-empty controls: "
          f"{sum(bool(c['mastg_tests']) for c in controls)}/{len(controls)}")


if __name__ == "__main__":
    main(sys.argv[1])
