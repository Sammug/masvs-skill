import builtins
import csv
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "masvs" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import make_report  # noqa: E402

try:
    import openpyxl
except ImportError:
    openpyxl = None

COLUMNS = [
    "Finding", "Affected Asset", "Observation", "Impact", "Severity", "Recommendation",
    "Status", "Remediation / Response", "Evidence", "Re-test Build", "Ticket",
    "MASVS Control", "MASWE",
]
TOKEN = "ghp_" + "a1B2c3D4e5" * 3 + "a1B2c3"


def finding(**kw):
    base = {
        "title": "Cleartext traffic allowed",
        "control": "MASVS-NETWORK-1",
        "maswe": "MASWE-0050",
        "asset": "Android app",
        "observation": "obs",
        "impact": "imp",
        "severity": "High",
        "recommendation": "rec",
        "status": "Fixed",
        "response": "done",
        "evidence": "ev",
        "evidence_kind": "verified",
        "retest_build": "1.0.1+2",
        "ticket": "EX-1",
    }
    base.update(kw)
    return base


def doc(*findings):
    return {"project": "Example App", "assets": ["Android app"], "generated": "2026-01-01",
            "findings": list(findings)}


def write(tmp_path, data):
    p = tmp_path / "findings.json"
    p.write_text(json.dumps(data))
    return p


def test_schema_rejects_bad_severity():
    errs = make_report.validate(doc(finding(severity="Severe")))
    assert errs and any("severity" in e for e in errs)


def test_unknown_control_rejected():
    errs = make_report.validate(doc(finding(control="MASVS-NOPE-9")))
    assert any("control" in e for e in errs)


def test_valid_document_passes():
    assert make_report.validate(doc(finding(maswe=["MASWE-1", "MASWE-2"]))) == []


def test_cli_validation_error_exits_2(tmp_path):
    p = write(tmp_path, doc(finding(severity="Severe")))
    r = subprocess.run([sys.executable, str(SCRIPTS / "make_report.py"), str(p), "--out", str(tmp_path / "o")],
                       capture_output=True, text=True)
    assert r.returncode == 2
    assert "error" in json.loads(r.stdout)


def test_markdown_has_summary_counts(tmp_path):
    p = write(tmp_path, doc(finding(), finding(title="B"),
                            finding(title="C", severity="Medium", status="False positive")))
    assert make_report.main([str(p), "--out", str(tmp_path / "out")]) == 0
    md = (tmp_path / "out" / "report.md").read_text()
    assert "# MASVS findings — Example App" in md
    assert "| High | 0 | 2 | 0 | 0 | 0 | 0 | 2 |" in md
    assert "| Medium | 0 | 0 | 0 | 1 | 0 | 0 | 1 |" in md


def test_markdown_escapes_pipes(tmp_path):
    p = write(tmp_path, doc(finding(observation="a|b\nc")))
    make_report.main([str(p), "--out", str(tmp_path)])
    assert "a\\|b c" in (tmp_path / "report.md").read_text()


@pytest.mark.skipif(openpyxl is None, reason="openpyxl missing")
def test_xlsx_columns(tmp_path):
    p = write(tmp_path, doc(finding(maswe=["A", "B"])))
    make_report.main([str(p), "--out", str(tmp_path)])
    ws = openpyxl.load_workbook(tmp_path / "report.xlsx").active
    assert [c.value for c in ws[1]] == COLUMNS
    assert ws["M2"].value == "A, B"
    assert ws["I2"].value.startswith("[verified] ")
    assert ws.freeze_panes == "B2"


def test_csv_fallback(tmp_path, monkeypatch):
    real = builtins.__import__

    def blocked(name, *a, **k):
        if name.split(".")[0] == "openpyxl":
            raise ImportError(name)
        return real(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", blocked)
    p = write(tmp_path, doc(finding()))
    make_report.main([str(p), "--out", str(tmp_path / "o")])
    monkeypatch.undo()
    assert (tmp_path / "o" / "report.csv").exists()
    assert not (tmp_path / "o" / "report.xlsx").exists()
    rows = list(csv.reader((tmp_path / "o" / "report.csv").open(encoding="utf-8-sig")))
    assert rows[0] == COLUMNS


def test_secret_never_rendered(tmp_path, monkeypatch):
    p = write(tmp_path, doc(finding(evidence=f"token {TOKEN} and key = \"Zx9Zx9Zx9Zx9Zx9Zx9Q1\"")))
    make_report.main([str(p), "--out", str(tmp_path / "x")])
    real = builtins.__import__

    def blocked(name, *a, **k):
        if name.split(".")[0] == "openpyxl":
            raise ImportError(name)
        return real(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", blocked)
    make_report.main([str(p), "--out", str(tmp_path / "c")])
    monkeypatch.undo()
    for f in [tmp_path / "x" / "report.md", tmp_path / "c" / "report.csv", tmp_path / "c" / "report.md"]:
        text = f.read_text(encoding="utf-8")
        assert TOKEN not in text and "Zx9Zx9Zx9Zx9Zx9Zx9Q1" not in text
    if openpyxl:
        ws = openpyxl.load_workbook(tmp_path / "x" / "report.xlsx").active
        assert TOKEN not in str(ws["I2"].value)
        assert "ghp_…" in ws["I2"].value
