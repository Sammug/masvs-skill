import re
import subprocess
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILL = ROOT / "masvs" / "SKILL.md"


def _frontmatter(text):
    m = re.match(r"---\n(.*?)\n---\n", text, re.S)
    assert m, "missing frontmatter"
    return m.group(1)


def _top_level(fm, key):
    m = re.search(rf"^{key}:\s*(.+)$", fm, re.M)
    return m.group(1).strip().strip("\"'") if m else None


def test_skill_frontmatter():
    fm = _frontmatter(SKILL.read_text())
    assert _top_level(fm, "name") == "masvs"
    desc = _top_level(fm, "description")
    assert desc and 1 <= len(desc) <= 1024
    assert "MASVS" in desc
    assert re.search(r"^metadata:\s*\n\s+version:\s*0\.1\.0\s*$", fm, re.M)


def test_package_zip(tmp_path):
    subprocess.run(["bash", str(ROOT / "scripts" / "package.sh")], check=True, cwd=tmp_path)
    zp = ROOT / "dist" / "masvs-0.1.0.zip"
    assert zp.exists()
    names = zipfile.ZipFile(zp).namelist()
    assert "masvs/SKILL.md" in names
    assert all(n.startswith("masvs/") for n in names)
    assert not any("__pycache__" in n or "tests/" in n for n in names)
