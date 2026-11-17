import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONTROLS = ROOT / "masvs" / "data" / "controls.json"
CONTROLS_MD = ROOT / "masvs" / "references" / "controls.md"
GEN = ROOT / "tools" / "gen_controls_md.py"

# Per-group control counts from https://mas.owasp.org/MASVS/ (fetched 2026-11-17).
EXPECTED_COUNTS = {
    "STORAGE": 2,
    "CRYPTO": 2,
    "AUTH": 3,
    "NETWORK": 2,
    "PLATFORM": 3,
    "CODE": 4,
    "RESILIENCE": 4,
    "PRIVACY": 4,
}


def load():
    return json.loads(CONTROLS.read_text())


def test_groups():
    assert {c["group"] for c in load()} == set(EXPECTED_COUNTS)


def test_ids_unique_and_wellformed():
    ids = [c["id"] for c in load()]
    assert len(ids) == len(set(ids))
    for c in load():
        assert re.fullmatch(r"MASVS-[A-Z]+-\d", c["id"])
        assert c["id"].startswith(f"MASVS-{c['group']}-")


def test_every_control_has_url():
    for c in load():
        assert c["url"].startswith("https://mas.owasp.org/")


def test_counts_match_source():
    assert dict(Counter(c["group"] for c in load())) == EXPECTED_COUNTS


def test_shape_and_summary_length():
    for c in load():
        assert set(c) == {"id", "group", "summary", "mastg_tests", "maswe", "url"}
        assert 0 < len(c["summary"].split()) <= 25
        assert all(re.fullmatch(r"MASWE-\d{4}", m) for m in c["maswe"])
        assert all(re.fullmatch(r"MASTG-TEST-\d{4}", t) for t in c["mastg_tests"])


def test_controls_md_matches_generator():
    out = subprocess.run(
        [sys.executable, str(GEN)], capture_output=True, text=True, check=True
    ).stdout
    assert CONTROLS_MD.read_text() == out
