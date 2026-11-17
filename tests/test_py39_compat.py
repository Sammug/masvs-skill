import ast
import subprocess
from pathlib import Path

import pytest

SCRIPTS = sorted((Path(__file__).resolve().parent.parent / "skills" / "masvs" / "scripts").glob("*.py"))
PY39 = Path("/usr/bin/python3")


def _has_future_annotations(tree):
    return any(
        isinstance(n, ast.ImportFrom) and n.module == "__future__"
        and any(a.name == "annotations" for a in n.names)
        for n in tree.body
    )


def _annotations(tree):
    for n in ast.walk(tree):
        if isinstance(n, ast.arg) and n.annotation:
            yield n.annotation
        elif isinstance(n, ast.FunctionDef) and n.returns:
            yield n.returns
        elif isinstance(n, ast.AnnAssign):
            yield n.annotation


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_pipe_annotations_need_future_import(script):
    tree = ast.parse(script.read_text(encoding="utf-8"))
    piped = any(
        isinstance(sub, ast.BinOp) and isinstance(sub.op, ast.BitOr)
        for ann in _annotations(tree) for sub in ast.walk(ann)
    )
    if piped:
        assert _has_future_annotations(tree), f"{script.name}: X | Y annotation without __future__ import"


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_every_script_has_future_import(script):
    assert _has_future_annotations(ast.parse(script.read_text(encoding="utf-8")))


def _is_py39():
    if not PY39.exists():
        return False
    out = subprocess.run([str(PY39), "-c", "import sys;print(sys.version_info[:2]==(3,9))"],
                         capture_output=True, text=True)
    return out.stdout.strip() == "True"


@pytest.mark.skipif(not _is_py39(), reason="/usr/bin/python3 is not 3.9")
@pytest.mark.parametrize("script", [s for s in SCRIPTS if not s.name.startswith("_")], ids=lambda p: p.name)
def test_help_runs_under_python39(script):
    r = subprocess.run([str(PY39), str(script), "--help"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
