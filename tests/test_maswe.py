import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "skills" / "masvs" / "data"
MASWE_MD = ROOT / "skills" / "masvs" / "references" / "maswe.md"
GEN = ROOT / "tools" / "gen_maswe.py"
FIELDS = {"id", "title", "requirement", "group", "controls", "platforms", "cwe", "modes", "mitigations", "url"}


def catalog():
    return json.loads((DATA / "maswe.json").read_text())


def weaknesses():
    return {w["id"]: w for w in catalog()["weaknesses"]}


def controls():
    return json.loads((DATA / "controls.json").read_text())


def rules():
    return json.loads((DATA / "rules.json").read_text())["rules"]


def test_catalog_pinned_to_release():
    doc = catalog()
    assert re.fullmatch(r"v\d+\.\d+\.\d+", doc["version"])
    assert doc["source"] == "https://github.com/OWASP/maswe"


def test_entries_complete_and_wellformed():
    ws = catalog()["weaknesses"]
    assert len(ws) == 78
    assert [w["id"] for w in ws] == sorted({w["id"] for w in ws})
    known_controls = {c["id"] for c in controls()}
    for w in ws:
        assert set(w) == FIELDS
        assert re.fullmatch(r"MASWE-\d{4}", w["id"])
        assert w["title"] and w["requirement"].startswith("The app")
        assert w["controls"] and set(w["controls"]) <= known_controls
        assert set(w["platforms"]) <= {"android", "ios"} and w["platforms"]
        assert w["modes"] and w["mitigations"]
        assert w["url"] == f"https://mas.owasp.org/MASWE/MASVS-{w['group']}/{w['id']}/"


def test_controls_json_agrees_with_catalog():
    ws = weaknesses()
    for c in controls():
        expected = sorted(i for i, w in ws.items() if c["id"] in w["controls"])
        assert c["maswe"] == expected, c["id"]


def test_rule_maswe_known_and_mapped_to_rule_control():
    ws = weaknesses()
    for r in rules():
        assert isinstance(r["maswe"], list), r["id"]
        for m in r["maswe"]:
            assert m in ws, (r["id"], m)
            assert r["control"] in ws[m]["controls"], (r["id"], m)


def test_most_rules_tagged():
    rs = rules()
    assert sum(bool(r["maswe"]) for r in rs) >= len(rs) * 0.6


def test_maswe_md_matches_generator():
    out = subprocess.run([sys.executable, str(GEN), "--md"], capture_output=True, text=True, check=True).stdout
    assert MASWE_MD.read_text() == out


def test_maswe_md_lists_every_weakness():
    text = MASWE_MD.read_text()
    for i, w in weaknesses().items():
        assert f"[{i}]({w['url']})" in text
