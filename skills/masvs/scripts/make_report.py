from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import redact, redact_literals  # noqa: E402

DATA = Path(__file__).resolve().parent.parent / "data"
SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]
STATUSES = ["Open", "Fixed", "Already mitigated", "False positive", "Risk accepted", "Not run"]
COLUMNS = [
    ("Finding", "title"), ("Affected Asset", "asset"), ("Observation", "observation"),
    ("Impact", "impact"), ("Severity", "severity"), ("Recommendation", "recommendation"),
    ("Status", "status"), ("Remediation / Response", "response"), ("Evidence", "evidence"),
    ("Re-test Build", "retest_build"), ("Ticket", "ticket"), ("MASVS Control", "control"),
    ("MASWE", "maswe"),
]
WIDTHS = [28, 18, 45, 35, 11, 45, 18, 40, 45, 14, 12, 18, 18]
FOOTNOTE = (
    "Evidence tags: [verified] a script or command showed it; "
    "[inferred] reasoned from code or config; [manual] needs manual test"
)
SEV_COLOURS = {"Critical": "C00000", "High": "FF0000", "Medium": "FFC000", "Low": "0070C0", "Info": "7F7F7F"}
STATUS_FILLS = {
    "Fixed": ("C6EFCE", "006100"), "Already mitigated": ("C6EFCE", "006100"),
    "False positive": ("FFEB9C", "9C5700"), "Risk accepted": ("FFEB9C", "9C5700"),
    "Open": ("FFC7CE", "9C0006"), "Not run": ("EDEDED", "595959"),
}

_TYPES = {
    "object": dict, "array": list, "string": str, "boolean": bool,
    "integer": int, "number": (int, float), "null": type(None),
}


def _type_ok(value, name: str) -> bool:
    if name in ("integer", "number") and isinstance(value, bool):
        return False
    return isinstance(value, _TYPES[name])


def _check(value, schema: dict, path: str, errors: list[str]) -> None:
    t = schema.get("type")
    if t is not None:
        names = t if isinstance(t, list) else [t]
        if not any(_type_ok(value, n) for n in names):
            errors.append(f"{path}: expected {'/'.join(names)}")
            return
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: {value!r} not one of {schema['enum']}")
    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path}: missing required '{key}'")
        for key, sub in schema.get("properties", {}).items():
            if key in value:
                _check(value[key], sub, f"{path}.{key}", errors)
    if isinstance(value, list) and "items" in schema:
        for i, item in enumerate(value):
            _check(item, schema["items"], f"{path}[{i}]", errors)


def validate(data) -> list[str]:
    schema = json.loads((DATA / "findings.schema.json").read_text(encoding="utf-8"))
    errors: list[str] = []
    _check(data, schema, "$", errors)
    if errors:
        return errors
    controls = {c["id"] for c in json.loads((DATA / "controls.json").read_text(encoding="utf-8"))}
    for i, f in enumerate(data["findings"]):
        if f["control"] not in controls:
            errors.append(f"$.findings[{i}].control: unknown control {f['control']!r}")
    for i, f in enumerate(data["findings"]):
        label = f"$.findings[{i}] ({f['title']})"
        evidence = str(f.get("evidence") or "").strip()
        kind = f.get("evidence_kind")
        status = f["status"]
        if status in ("Fixed", "Already mitigated") and not (evidence and kind == "verified"):
            errors.append(f"{label}: status {status} requires non-empty evidence with evidence_kind 'verified'")
        if status == "Fixed" and not str(f.get("retest_build") or "").strip():
            errors.append(f"{label}: status Fixed requires a non-empty retest_build")
        if status == "False positive" and not (evidence and kind in ("verified", "inferred")):
            errors.append(f"{label}: status False positive requires non-empty evidence with evidence_kind 'verified' or 'inferred', not manual")
    return errors


def clean(value) -> str:
    return redact_literals(redact(str(value)))


def cell(f: dict, key: str) -> str:
    v = f.get(key, "")
    if v is None:
        v = ""
    if key == "maswe" and isinstance(v, list):
        v = ", ".join(str(x) for x in v)
    text = clean(v)
    if key == "evidence" and text and f.get("evidence_kind"):
        text = f"[{f['evidence_kind']}] {text}"
    return text


def rows(findings: list[dict]) -> list[list[str]]:
    return [[cell(f, key) for _, key in COLUMNS] for f in findings]


_FORMULA_RE = re.compile(r"^[=+\-@\t\r]")


def neutralise(text: str) -> str:
    return "'" + text if _FORMULA_RE.match(text) else text


def md_cell(text: str) -> str:
    return re.sub(r"\s*\n\s*", " ", text.replace("\r", "")).replace("|", "\\|")


def render_markdown(data: dict, table: list[list[str]]) -> str:
    counts = {s: {st: 0 for st in STATUSES} for s in SEVERITIES}
    for f in data["findings"]:
        counts[f["severity"]][f["status"]] += 1
    out = [
        f"# MASVS findings — {md_cell(clean(data['project']))}",
        "",
        f"Generated: {md_cell(clean(data.get('generated') or date.today().isoformat()))}",
        "",
        "## Assets",
        "",
        *[f"- {md_cell(clean(a))}" for a in data["assets"]],
        "",
        "## Summary",
        "",
        "| Severity | " + " | ".join(STATUSES) + " | Total |",
        "|" + "---|" * (len(STATUSES) + 2),
    ]
    col_tot = {st: 0 for st in STATUSES}
    for sev in SEVERITIES:
        row = [counts[sev][st] for st in STATUSES]
        for st, n in zip(STATUSES, row):
            col_tot[st] += n
        out.append(f"| {sev} | " + " | ".join(map(str, row)) + f" | {sum(row)} |")
    out.append("| Total | " + " | ".join(str(col_tot[st]) for st in STATUSES) + f" | {sum(col_tot.values())} |")
    out += ["", "## Findings", "", "| " + " | ".join(n for n, _ in COLUMNS) + " |",
            "|" + "---|" * len(COLUMNS)]
    out += ["| " + " | ".join(md_cell(c) for c in r) + " |" for r in table]
    out += ["", f"_{FOOTNOTE}_", ""]
    return "\n".join(out)


def write_csv(path: Path, table: list[list[str]]) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow([n for n, _ in COLUMNS])
        w.writerows([neutralise(c) for c in r] for r in table)


def write_xlsx(openpyxl, path: Path, table: list[list[str]]) -> None:
    from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
    from openpyxl.utils import get_column_letter

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Findings"
    base = Font(name="Aptos", size=11)
    side = Side(style="thin")
    border = Border(left=side, right=side, top=side, bottom=side)
    align = Alignment(wrap_text=True, vertical="top")
    ws.append([n for n, _ in COLUMNS])
    for r in table:
        ws.append([neutralise(c) for c in r])
    sev_i = [k for _, k in COLUMNS].index("severity")
    st_i = [k for _, k in COLUMNS].index("status")
    for row in ws.iter_rows(min_row=1, max_row=ws.max_row):
        for c in row:
            c.font = Font(name="Aptos", size=11, bold=True) if c.row == 1 else base
            c.alignment = align
            if c.row > 1 and isinstance(c.value, str):
                c.data_type = "s"
            c.border = border
        if row[0].row == 1:
            continue
        sev = row[sev_i]
        if sev.value in SEV_COLOURS:
            sev.font = Font(name="Aptos", size=11, bold=True, color=SEV_COLOURS[sev.value])
        st = row[st_i]
        if st.value in STATUS_FILLS:
            fill, fg = STATUS_FILLS[st.value]
            st.fill = PatternFill("solid", start_color=fill, end_color=fill)
            st.font = Font(name="Aptos", size=11, color=fg)
    for i, w in enumerate(WIDTHS, 1):
        ws.column_dimensions[get_column_letter(i)].width = w
    ws.freeze_panes = "B2"
    ws.auto_filter.ref = f"A1:{get_column_letter(len(COLUMNS))}{ws.max_row}"
    foot = ws.max_row + 2
    ws.cell(row=foot, column=1, value=FOOTNOTE).font = Font(name="Aptos", size=11, italic=True)
    wb.save(path)


def emit(obj: dict, code: int = 0) -> int:
    print(json.dumps(obj))
    return code


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Render findings.json to Markdown and Excel/CSV.")
    ap.add_argument("findings")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    try:
        data = json.loads(Path(args.findings).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return emit({"error": "cannot read findings", "details": [clean(e)]}, 2)
    errors = validate(data)
    if errors:
        return emit({"error": "invalid findings", "details": [clean(e) for e in errors]}, 2)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    table = rows(data["findings"])
    md = out / "report.md"
    md.write_text(render_markdown(data, table), encoding="utf-8")
    try:
        import openpyxl
    except ImportError:
        openpyxl = None
    if openpyxl:
        second = out / "report.xlsx"
        write_xlsx(openpyxl, second, table)
    else:
        second = out / "report.csv"
        write_csv(second, table)
    return emit({"written": [str(md), str(second)]})


if __name__ == "__main__":
    sys.exit(main())
