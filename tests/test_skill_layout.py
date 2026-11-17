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


def _top_level_meta_version(fm):
    m = re.search(r"^metadata:\s*\n\s+version:\s*(\S+)\s*$", fm, re.M)
    assert m, "metadata.version missing"
    return m.group(1).strip("\"'")


def test_skill_frontmatter():
    fm = _frontmatter(SKILL.read_text())
    assert _top_level(fm, "name") == "masvs"
    desc = _top_level(fm, "description")
    assert desc and 1 <= len(desc) <= 1024
    assert "MASVS" in desc
    assert re.match(r"\d+\.\d+\.\d+$", _top_level_meta_version(fm))


def test_package_zip(tmp_path):
    subprocess.run(["bash", str(ROOT / "scripts" / "package.sh")], check=True, cwd=tmp_path)
    version = _top_level_meta_version(_frontmatter(SKILL.read_text()))
    zp = ROOT / "dist" / f"masvs-{version}.zip"
    assert zp.exists()
    names = zipfile.ZipFile(zp).namelist()
    assert "masvs/SKILL.md" in names
    assert all(n.startswith("masvs/") for n in names)
    assert not any("__pycache__" in n or "tests/" in n for n in names)
