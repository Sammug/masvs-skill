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


def test_heading_and_generated_redacted_and_escaped(tmp_path):
    d = doc(finding())
    d["project"] = f"Ex\nApp {TOKEN}"
    d["generated"] = f"2026\n{TOKEN}"
    p = write(tmp_path, d)
    make_report.main([str(p), "--out", str(tmp_path)])
    md = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert TOKEN not in md
    assert "# MASVS findings — Ex App ghp_…" in md
    assert "Generated: 2026 ghp_…" in md


FORMULA = '=HYPERLINK("http://example.invalid","x")'


@pytest.mark.skipif(openpyxl is None, reason="openpyxl missing")
def test_xlsx_formula_neutralised(tmp_path):
    p = write(tmp_path, doc(finding(observation=FORMULA)))
    make_report.main([str(p), "--out", str(tmp_path)])
    c = openpyxl.load_workbook(tmp_path / "report.xlsx").active["C2"]
    assert c.data_type == "s"
    assert c.value == "'" + FORMULA


def test_csv_formula_neutralised(tmp_path, monkeypatch):
    real = builtins.__import__

    def blocked(name, *a, **k):
        if name.split(".")[0] == "openpyxl":
            raise ImportError(name)
        return real(name, *a, **k)

    p = write(tmp_path, doc(finding(observation=FORMULA)))
    monkeypatch.setattr(builtins, "__import__", blocked)
    make_report.main([str(p), "--out", str(tmp_path / "o")])
    monkeypatch.undo()
    rows = list(csv.reader((tmp_path / "o" / "report.csv").open(encoding="utf-8-sig")))
    assert rows[1][2] == "'" + FORMULA


def test_evidence_kind_required_on_every_finding():
    for status, ev in (("Open", "ev"), ("Not run", "")):
        f = finding(status=status, evidence=ev)
        del f["evidence_kind"]
        errs = make_report.validate(doc(f))
        assert any("evidence_kind" in e and "[0]" in e for e in errs), status


def test_false_positive_rejects_manual_kind():
    errs = make_report.validate(doc(finding(status="False positive", evidence="x", evidence_kind="manual")))
    assert any("False positive" in e and "manual" in e for e in errs)
    for kind in ("verified", "inferred"):
        assert make_report.validate(doc(finding(status="False positive", evidence="x", evidence_kind=kind))) == []


@pytest.mark.parametrize("retest", ["", "   ", None])
def test_fixed_requires_retest_build(retest):
    f = finding(status="Fixed")
    if retest is None:
        del f["retest_build"]
    else:
        f["retest_build"] = retest
    errs = make_report.validate(doc(f))
    assert any("retest_build" in e for e in errs)


def test_already_mitigated_does_not_need_retest_build():
    f = finding(status="Already mitigated")
    del f["retest_build"]
    assert make_report.validate(doc(f)) == []


def test_validation_details_never_echo_secrets(tmp_path):
    bad = doc(finding(title=f"leak {TOKEN}", severity=f"Sev {TOKEN}", control=f"X {TOKEN}", status="Open"))
    p = write(tmp_path, bad)
    r = subprocess.run([sys.executable, str(SCRIPTS / "make_report.py"), str(p), "--out", str(tmp_path / "o")],
                       capture_output=True, text=True)
    assert r.returncode == 2
    assert TOKEN not in r.stdout
    bad = doc(finding(title=f"leak {TOKEN}", status="Fixed", evidence="", retest_build=""))
    p = write(tmp_path, bad)
    r = subprocess.run([sys.executable, str(SCRIPTS / "make_report.py"), str(p), "--out", str(tmp_path / "o")],
                       capture_output=True, text=True)
    assert r.returncode == 2 and TOKEN not in r.stdout and "ghp_" in r.stdout


@pytest.mark.parametrize("status", ["Fixed", "Already mitigated"])
@pytest.mark.parametrize("kw", [{"evidence": ""}, {"evidence_kind": "inferred"}, {"evidence_kind": "manual"}])
def test_fixed_requires_verified_evidence(status, kw):
    errs = make_report.validate(doc(finding(status=status, **kw)))
    assert any("verified" in e and "Cleartext traffic allowed" in e and "[0]" in e for e in errs)


def test_false_positive_requires_evidence():
    assert make_report.validate(doc(finding(status="False positive", evidence="", evidence_kind="inferred")))
    assert make_report.validate(doc(finding(status="False positive", evidence="x", evidence_kind="inferred"))) == []


def test_footnote_wording():
    assert "[verified] a script or command showed it" in make_report.FOOTNOTE
    assert "[manual] needs manual test" in make_report.FOOTNOTE
