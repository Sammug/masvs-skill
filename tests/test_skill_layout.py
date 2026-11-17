import re
import shutil
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


def _git(cwd, *args):
    subprocess.run(["git", "-c", "user.email=t@example.invalid", "-c", "user.name=t", *args],
                   check=True, cwd=cwd, capture_output=True)


def _repo_copy(tmp_path):
    repo = tmp_path / "repo"
    shutil.copytree(ROOT / "masvs", repo / "masvs", ignore=shutil.ignore_patterns("__pycache__"))
    (repo / "scripts").mkdir()
    shutil.copy(ROOT / "scripts" / "package.sh", repo / "scripts" / "package.sh")
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "init")
    return repo


def _package(repo):
    return subprocess.run(["bash", str(repo / "scripts" / "package.sh")], cwd=repo.parent,
                          capture_output=True, text=True)


def test_package_zip(tmp_path):
    repo = _repo_copy(tmp_path)
    r = _package(repo)
    assert r.returncode == 0, r.stderr
    version = _top_level_meta_version(_frontmatter(SKILL.read_text()))
    zp = repo / "dist" / f"masvs-{version}.zip"
    assert zp.exists()
    names = zipfile.ZipFile(zp).namelist()
    assert "masvs/SKILL.md" in names
    assert all(n.startswith("masvs/") for n in names)
    assert not any("__pycache__" in n or "tests/" in n for n in names)
    assert not any(n.endswith(".gitkeep") for n in names)


def test_package_refuses_dirty_masvs(tmp_path):
    repo = _repo_copy(tmp_path)
    (repo / "masvs" / "SKILL.md").write_text((repo / "masvs" / "SKILL.md").read_text() + "\nedit\n")
    r = _package(repo)
    assert r.returncode != 0
    assert "uncommitted" in r.stderr
    assert not list((repo / "dist").glob("*.zip")) if (repo / "dist").exists() else True
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "edit")
    assert _package(repo).returncode == 0
