import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "masvs" / "scripts"
FIX = ROOT / "tests" / "fixtures" / "stacks"
sys.path.insert(0, str(SCRIPTS))

import _common  # noqa: E402
import detect_stack  # noqa: E402


def test_flutter():
    r = detect_stack.detect(FIX / "flutter")
    assert "flutter" in r["stacks"]
    assert "android/app/src/main/AndroidManifest.xml" in r["android_manifests"]
    assert r["ios_plists"] == ["ios/Runner/Info.plist"]
    assert "pubspec.yaml" in r["dependency_files"]


def test_rn():
    r = detect_stack.detect(FIX / "rn")
    assert r["stacks"] == ["react-native"]
    assert r["dependency_files"] == ["package.json"]


def test_native_android_and_ios():
    a = detect_stack.detect(FIX / "android")
    assert a["stacks"] == ["android"]
    assert "app/build.gradle.kts" in a["dependency_files"]
    assert detect_stack.detect(FIX / "ios")["stacks"] == ["ios"]


def test_mono():
    r = detect_stack.detect(FIX / "mono")
    assert {"flutter", "android", "ios"} <= set(r["stacks"])
    assert r["ios_plists"] == ["ios/Runner/Info.plist", "ios/ShareExt/Info.plist"]
    assert r["android_manifests"] == ["android-lib/src/main/AndroidManifest.xml"]
    assert r["stacks"] == sorted(set(r["stacks"]))


def test_ignored_dirs(tmp_path):
    for d in ("build", "Pods", "node_modules"):
        p = tmp_path / d / "x"
        p.mkdir(parents=True)
        (p / "AndroidManifest.xml").write_text("<manifest/>")
        (p / "Info.plist").write_text("<plist/>")
    r = detect_stack.detect(tmp_path)
    assert r["android_manifests"] == [] and r["ios_plists"] == []
    assert r["stacks"] == []


def test_gradle_without_android_plugin(tmp_path):
    (tmp_path / "build.gradle").write_text("plugins { id 'java' }")
    assert detect_stack.detect(tmp_path)["stacks"] == []


def test_xcodeproj_marks_ios(tmp_path):
    (tmp_path / "App.xcodeproj").mkdir()
    (tmp_path / "App.xcodeproj" / "project.pbxproj").write_text("")
    assert detect_stack.detect(tmp_path)["stacks"] == ["ios"]


def test_malformed_package_json(tmp_path):
    (tmp_path / "package.json").write_text("{not json")
    r = detect_stack.detect(tmp_path)
    assert r["stacks"] == []


def run_cli(*args):
    return subprocess.run(
        [sys.executable, str(SCRIPTS / "detect_stack.py"), *args],
        capture_output=True, text=True, cwd="/",
    )


def test_cli_ok():
    p = run_cli(str(FIX / "rn"))
    assert p.returncode == 0
    assert json.loads(p.stdout)["stacks"] == ["react-native"]


def test_cli_missing_root(tmp_path):
    p = run_cli(str(tmp_path / "nope"))
    assert p.returncode == 2
    assert "error" in json.loads(p.stdout)


def test_cli_root_is_file(tmp_path):
    f = tmp_path / "f.txt"
    f.write_text("x")
    p = run_cli(str(f))
    assert p.returncode == 2
    assert "error" in json.loads(p.stdout)


def make_tree(tmp_path):
    for rel in ("a.txt", "src/b.txt", "node_modules/m/c.txt", "build/d.txt",
                "vendor/v/e.txt", "node_modules/.git/f.txt", "Pods/p.txt"):
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("")
    return tmp_path


def rel(root, it):
    return sorted(str(p.relative_to(root)) for p in it)


def test_walk_prunes(tmp_path):
    root = make_tree(tmp_path)
    assert rel(root, _common.walk(root)) == ["a.txt", "src/b.txt"]


def test_walk_include_deps(tmp_path):
    root = make_tree(tmp_path)
    got = rel(root, _common.walk(root, include_deps=True))
    assert got == ["Pods/p.txt", "a.txt", "node_modules/m/c.txt",
                   "src/b.txt", "vendor/v/e.txt"]


def test_constants():
    assert _common.IGNORE_DIRS == frozenset(
        {"build", ".dart_tool", "node_modules", "Pods", ".gradle", "DerivedData", ".git", "vendor"})
    assert _common.DEP_DIRS == frozenset({"node_modules", "Pods", "vendor", ".pub-cache"})
