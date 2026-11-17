#!/usr/bin/env python3
"""Build the MASWE catalog from a clone of github.com/OWASP/maswe.

Usage:
  gen_maswe.py <maswe_clone>   rewrite skills/masvs/data/maswe.json (check out a release tag first)
  gen_maswe.py --md            print references/maswe.md generated from maswe.json
"""
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "skills" / "masvs" / "data" / "maswe.json"
GROUPS = ["STORAGE", "CRYPTO", "AUTH", "NETWORK", "PLATFORM", "CODE", "RESILIENCE", "PRIVACY"]


def _list(fm: str, key: str) -> list:
    m = re.search(rf"^\s*{key}:\s*\[(.*?)\]", fm, re.M)
    return [x.strip() for x in m.group(1).split(",") if x.strip()] if m else []


def _labels(body: str, heading: str) -> list:
    m = re.search(rf"^## {heading}\n(.*?)(?=^## |\Z)", body, re.S | re.M)
    return re.findall(r"^- \*\*(.+?)\*\*", m.group(1), re.M) if m else []


def parse(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    fm, body = re.match(r"---\n(.*?)\n---\n(.*)", text, re.S).groups()

    def scalar(key):
        return re.search(rf"^{key}:\s*(.*)$", fm, re.M).group(1).strip().strip('"')

    group = path.parent.name
    return {
        "id": scalar("id"),
        "title": scalar("title"),
        "requirement": scalar("requirement"),
        "group": group.removeprefix("MASVS-"),
        "controls": sorted(_list(fm, "masvs-v2")),
        "platforms": _list(fm, "platform"),
        "cwe": [int(x) for x in _list(fm, "cwe")],
        "modes": _labels(body, "Modes of Introduction"),
        "mitigations": _labels(body, "Mitigations"),
        "url": f"https://mas.owasp.org/MASWE/{group}/{scalar('id')}/",
    }


def build(clone: str) -> None:
    clone = Path(clone)
    tag = subprocess.run(["git", "-C", str(clone), "describe", "--tags", "--exact-match"],
                         capture_output=True, text=True).stdout.strip()
    if not tag:
        sys.exit("check out a MASWE release tag first (git checkout vX.Y.Z)")
    items = sorted((parse(p) for p in clone.glob("weaknesses/*/MASWE-*.md")), key=lambda w: w["id"])
    doc = {"version": tag, "source": "https://github.com/OWASP/maswe", "weaknesses": items}
    DATA.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"{len(items)} weaknesses from MASWE {tag}")


def cell(text: str) -> str:
    return text.replace("|", "\\|")


def render(doc: dict) -> str:
    lines = [
        "# MASWE weaknesses",
        "",
        f"OWASP MASWE {doc['version']} (https://mas.owasp.org/MASWE/), CC BY-SA 4.0. "
        "Titles and requirements are quoted; mitigations are the source's headings.",
        "",
        "Full entries (modes of introduction, CWE, platforms) are in `data/maswe.json`. "
        "Read the linked page before citing a weakness you have not used before.",
    ]
    for group in GROUPS:
        lines += ["", f"## {group}", "",
                  "| MASWE | Weakness | Requirement | Controls | Mitigations |",
                  "|---|---|---|---|---|"]
        for w in doc["weaknesses"]:
            if w["group"] != group:
                continue
            title = w["title"] + ("" if w["platforms"] == ["android", "ios"] else f" ({', '.join(w['platforms'])} only)")
            controls = ", ".join(c.removeprefix("MASVS-") for c in w["controls"])
            lines.append(f"| [{w['id']}]({w['url']}) | {cell(title)} | {cell(w['requirement'])} "
                         f"| {controls} | {cell('; '.join(w['mitigations']) or '-')} |")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    if sys.argv[1:] == ["--md"]:
        print(render(json.loads(DATA.read_text())), end="")
    elif len(sys.argv) == 2:
        build(sys.argv[1])
    else:
        sys.exit(__doc__)
