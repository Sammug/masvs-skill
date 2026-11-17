import json
import os
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SKILL = ROOT / "masvs"
REFS = SKILL / "references"
GROUPS = ["storage", "crypto", "auth", "network", "platform", "code", "resilience", "privacy"]
SECTIONS = [
    "## Controls",
    "## What to check",
    "## Fix patterns",
    "## Evidence to show the auditor",
    "## Common false positives",
]
RULE_ID = re.compile(r"\b(?!MASVS-|MASTG-|MASWE-)[A-Z]+-[A-Z]+-\d+\b")
FP_FIELDS = ["**Symptom:**", "**Why it's a false positive:**", "**Evidence:**", "**Response:**"]


def controls():
    data = json.loads((SKILL / "data" / "controls.json").read_text())
    return data if isinstance(data, list) else data["controls"]


def rule_ids():
    return {r["id"] for r in json.loads((SKILL / "data" / "rules.json").read_text())["rules"]}


def reference_files():
    return [REFS / f"{g}.md" for g in GROUPS] + [REFS / "false-positives.md"]


@pytest.mark.parametrize("group", GROUPS)
def test_each_group_file_has_sections(group):
    text = (REFS / f"{group}.md").read_text()
    headings = [line.strip() for line in text.splitlines() if line.startswith("## ")]
    assert headings == SECTIONS


@pytest.mark.parametrize("group", GROUPS)
def test_group_file_cites_its_controls(group):
    text = (REFS / f"{group}.md").read_text()
    for c in controls():
        if c["group"] == group.upper():
            assert c["id"] in text
            assert c["url"] in text


@pytest.mark.parametrize("group", GROUPS)
def test_group_file_is_short(group):
    assert len((REFS / f"{group}.md").read_text().splitlines()) <= 200


def test_rule_ids_referenced_exist():
    known = rule_ids()
    unknown = {
        (p.name, tok)
        for p in reference_files()
        for tok in RULE_ID.findall(p.read_text())
        if tok not in known
    }
    assert not unknown


def test_false_positive_entries_are_complete():
    text = (REFS / "false-positives.md").read_text()
    entries = re.split(r"^## ", text, flags=re.M)[1:]
    assert len(entries) >= 6
    for entry in entries:
        for field in FP_FIELDS:
            assert field in entry, (entry.splitlines()[0], field)
        assert "scripts/" in entry


def test_false_positives_cover_known_patterns():
    text = (REFS / "false-positives.md").read_text().lower()
    for needle in ["path_provider", "app.framework", "aes/cbc/pkcs5padding", "strandhogg", "swift"]:
        assert needle in text


def test_no_client_identifiers():
    raw = os.environ.get("MASVS_DENYLIST", "")
    words = [w.strip().lower() for w in raw.split(",") if w.strip()]
    if not words:
        pytest.skip("MASVS_DENYLIST not set")
    hits = []
    for p in SKILL.rglob("*"):
        if not p.is_file() or "__pycache__" in p.parts:
            continue
        text = p.read_text(errors="ignore").lower()
        hits += [(p.relative_to(ROOT).as_posix(), w) for w in words if w in text]
    assert not hits
