#!/usr/bin/env python3
"""Print masvs/references/controls.md generated from masvs/data/controls.json."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "masvs" / "data" / "controls.json"


def render(controls):
    lines = [
        "# MASVS controls",
        "",
        "OWASP MASVS v2.1.0 (https://mas.owasp.org/MASVS/), CC BY-SA 4.0, paraphrased.",
        "",
        "Version source: latest release tag of github.com/OWASP/masvs (v2.1.0). MASTG tests are mapped via shared MASWE ids.",
        "",
        "| Control | Summary | MASWE | MASTG tests |",
        "|---|---|---|---|",
    ]
    for c in controls:
        maswe = ", ".join(c["maswe"]) or "-"
        tests = ", ".join(c["mastg_tests"]) or "-"
        lines.append(f"| [{c['id']}]({c['url']}) | {c['summary']} | {maswe} | {tests} |")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    print(render(json.loads(DATA.read_text())), end="")
