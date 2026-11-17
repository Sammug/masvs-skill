import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "masvs" / "scripts"
FIX = ROOT / "tests" / "fixtures" / "artifacts"
sys.path.insert(0, str(SCRIPTS))

import inspect_apk  # noqa: E402
import inspect_ipa  # noqa: E402


def fx(name):
    return (FIX / name).read_text()


def run_cli(script, arg, env):
    return subprocess.run(
        [sys.executable, str(SCRIPTS / script), str(arg)],
        capture_output=True, text=True, env=env,
    )


def test_parse_badging_sdks():
    b = inspect_apk.parse_badging(fx("aapt_badging.txt"))
    assert b["min_sdk"] == 29
    assert b["target_sdk"] == 36
    assert "android.permission.INTERNET" in b["permissions"]
    assert b["permissions"].count("android.permission.CAMERA") == 1


def test_parse_xmltree_backup_false():
    m = inspect_apk.parse_xmltree(fx("aapt_xmltree.txt"))
    assert m["allow_backup"] is False
    assert m["debuggable"] is False
    assert m["uses_cleartext"] is None
    assert m["network_security_config"] == "@0x7f110005"
    assert m["target_sdk"] == 36


def test_exported_without_permission_listed():
    m = inspect_apk.parse_xmltree(fx("aapt_xmltree.txt"))
    by_name = {e["name"]: e["permission"] for e in m["exported"]}
    assert by_name["com.example.app.MainActivity"] is None
    assert by_name["com.example.app.SyncService"] == "com.example.app.SYNC"
    assert "com.example.app.ScannerActivity" not in by_name
    assert "com.example.app.FileProvider" not in by_name


def test_intent_filter_implies_export_below_api_31():
    text = fx("aapt_xmltree.txt")
    old = inspect_apk.parse_xmltree(text.replace("targetSdkVersion(0x01010270)=36", "targetSdkVersion(0x01010270)=30"))
    assert "com.example.app.BootReceiver" in {e["name"] for e in old["exported"]}
    new = inspect_apk.parse_xmltree(text)
    assert "com.example.app.BootReceiver" not in {e["name"] for e in new["exported"]}


def test_debuggable_true_detected():
    text = fx("aapt_xmltree.txt").replace(
        "        A: http://schemas.android.com/apk/res/android:allowBackup(0x01010280)=false",
        "        A: http://schemas.android.com/apk/res/android:debuggable(0x0101000f)=true\n"
        "        A: http://schemas.android.com/apk/res/android:allowBackup(0x01010280)=true\n"
        "        A: http://schemas.android.com/apk/res/android:usesCleartextTraffic(0x010104ec)=true",
    )
    m = inspect_apk.parse_xmltree(text)
    assert m["debuggable"] is True
    assert m["allow_backup"] is True
    assert m["uses_cleartext"] is True


def test_otool_canary_present():
    r = inspect_ipa.parse_otool_imports(fx("otool_Iv_runner.txt"), "Runner")
    assert r["stack_canary"] is True
    assert r["arc"] is True
    assert r["kind"] == "objc-swift"


def test_otool_canary_absent_pure_swift():
    r = inspect_ipa.parse_otool_imports("0x1 1 _swift_allocObject\n0x2 2 _swift_release\n", "Lib")
    assert r["stack_canary"] is None
    assert r["arc"] is None
    assert r["kind"] == "objc-swift"
    assert "pure Swift" in r["note"]
    assert "ARC" in r["note"]


def test_objc_without_canary_is_false():
    r = inspect_ipa.parse_otool_imports("0x1 1 _objc_release\n0x2 2 _swift_allocObject\n", "Lib")
    assert r["stack_canary"] is False
    assert r["arc"] is True


def test_app_framework_dart_aot():
    r = inspect_ipa.parse_otool_imports(fx("otool_Iv_appframework.txt"), "App")
    assert r["kind"] == "dart-aot"
    assert r["arc"] is None
    assert r["stack_canary"] is None
    assert "n/a" in r["note"]


def test_plain_c_binary():
    r = inspect_ipa.parse_otool_imports("0x1 1 _malloc\n0x2 2 ___stack_chk_fail\n", "libfoo")
    assert r["kind"] == "c"
    assert r["stack_canary"] is True
    assert r["arc"] is None


def test_pie_from_header():
    assert inspect_ipa.parse_otool_header(fx("otool_hv.txt"))["pie"] is True
    assert inspect_ipa.parse_otool_header(fx("otool_hv_nopie.txt"))["pie"] is False
    assert inspect_ipa.parse_otool_header(fx("otool_hv_dylib.txt"))["pie"] is True


def test_ats_extraction():
    info = json.loads(fx("Info.plist"))
    assert inspect_ipa.ats_from_info(info)["NSAllowsArbitraryLoads"] is False
    assert inspect_ipa.ats_from_info({}) == {}


def test_missing_tool_skips(tmp_path, monkeypatch):
    f = tmp_path / "x.apk"
    f.write_bytes(b"PK")
    env = {"PATH": "", "HOME": str(tmp_path)}
    r = run_cli("inspect_apk.py", f, env)
    assert r.returncode == 0
    assert "skipped" in json.loads(r.stdout)
    g = tmp_path / "x.ipa"
    g.write_bytes(b"PK")
    r = run_cli("inspect_ipa.py", g, env)
    assert r.returncode == 0
    assert "skipped" in json.loads(r.stdout)


def test_bad_path_exits_2(tmp_path):
    env = {"PATH": "", "HOME": str(tmp_path)}
    for script in ("inspect_apk.py", "inspect_ipa.py"):
        r = run_cli(script, tmp_path / "nope", env)
        assert r.returncode == 2
        assert "error" in json.loads(r.stdout)


def fake_aapt2(tmp_path, body):
    d = tmp_path / "bin"
    d.mkdir()
    tool = d / "aapt2"
    tool.write_text("#!/bin/sh\n" + body + "\n")
    tool.chmod(0o755)
    return {"PATH": str(d), "HOME": str(tmp_path)}


def test_tool_failure_is_error_not_clean(tmp_path):
    f = tmp_path / "x.apk"
    f.write_bytes(b"PK")
    for body in ("echo 'boom' >&2; exit 1", "echo garbage", "exit 0"):
        d = tmp_path / ("t%d" % abs(hash(body)))
        d.mkdir()
        r = run_cli("inspect_apk.py", f, fake_aapt2(d, body))
        assert r.returncode == 2, body
        out = json.loads(r.stdout)
        assert "aapt2 failed" in out["error"]


def test_target_sdk_from_badging_drives_implicit_export():
    text = fx("aapt_xmltree.txt").replace("        A: http://schemas.android.com/apk/res/android:targetSdkVersion(0x01010270)=36\n", "")
    old = inspect_apk.parse_xmltree(text, 30)
    assert "com.example.app.BootReceiver" in {e["name"] for e in old["exported"]}
    assert old["target_sdk"] == 30
    new = inspect_apk.parse_xmltree(text, 36)
    assert "com.example.app.BootReceiver" not in {e["name"] for e in new["exported"]}


def test_unknown_target_sdk_marks_export_unknown():
    text = fx("aapt_xmltree.txt").replace("        A: http://schemas.android.com/apk/res/android:targetSdkVersion(0x01010270)=36\n", "")
    m = inspect_apk.parse_xmltree(text)
    entry = next(e for e in m["exported"] if e["name"] == "com.example.app.BootReceiver")
    assert entry["exported"] == "unknown"
    assert entry["permission"] is None


def test_pure_swift_with_canary_has_no_canary_note():
    r = inspect_ipa.parse_otool_imports("0x1 1 _swift_allocObject\n0x2 2 ___stack_chk_fail\n", "Lib")
    assert r["stack_canary"] is True
    assert r["arc"] is None
    assert "canary" not in (r["note"] or "")


def _debuggable_text(value):
    return fx("aapt_xmltree.txt").replace(
        "        A: http://schemas.android.com/apk/res/android:allowBackup(0x01010280)=false",
        f"        A: http://schemas.android.com/apk/res/android:debuggable(0x0101000f){value}\n"
        "        A: http://schemas.android.com/apk/res/android:allowBackup(0x01010280)=false",
    )


def test_debuggable_absent_is_false_without_note():
    m = inspect_apk.parse_xmltree(fx("aapt_xmltree.txt"))
    assert m["debuggable"] is False
    assert m["notes"] == []


@pytest.mark.parametrize("value", ["=@0x7f050001", '="${debug}"', "=0x7f050001"])
def test_debuggable_unresolved_is_null_with_note(value):
    m = inspect_apk.parse_xmltree(_debuggable_text(value))
    assert m["debuggable"] is None
    assert any("debuggable" in n for n in m["notes"])


def test_debuggable_unresolved_in_apkanalyzer_xml():
    xml = ('<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
           '<application android:debuggable="@bool/dbg"/></manifest>')
    m = inspect_apk.parse_manifest_xml(xml)
    assert m["debuggable"] is None
    assert any("debuggable" in n for n in m["notes"])


def _fake_ipa(tmp_path, main_plist, appex_plist):
    app = tmp_path / "Payload" / "Demo.app"
    appex = app / "PlugIns" / "Share.appex"
    appex.mkdir(parents=True)
    (app / "Info.plist").write_text(main_plist)
    (app / "Demo").write_bytes(b"x")
    (appex / "Info.plist").write_text(appex_plist)
    (appex / "Share").write_bytes(b"x")
    return tmp_path


def _fake_run(cmd):
    if cmd[0] == "plutil":
        return Path(cmd[-1]).read_text()
    if cmd[1] == "-hv":
        return fx("otool_hv.txt")
    return fx("otool_Iv_runner.txt")


MAIN_PLIST = json.dumps({"CFBundleIdentifier": "com.example.demo", "CFBundleExecutable": "Demo",
                         "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": False}})
APPEX_PLIST = json.dumps({"CFBundleIdentifier": "com.example.demo.share", "CFBundleExecutable": "Share",
                          "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True}})


def test_appex_binaries_and_ats_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(inspect_ipa, "run", _fake_run)
    r = inspect_ipa.inspect_app("otool", "plutil", _fake_ipa(tmp_path, MAIN_PLIST, APPEX_PLIST))
    paths = [b["path"] for b in r["binaries"]]
    assert "Demo.app/Demo" in paths
    assert "PlugIns/Share.appex/Share" in paths
    assert r["ats"] == {"NSAllowsArbitraryLoads": False}
    by_id = {b["bundle_id"]: b for b in r["bundles"]}
    assert by_id["com.example.demo"]["ats"] == {"NSAllowsArbitraryLoads": False}
    assert by_id["com.example.demo.share"]["ats"] == {"NSAllowsArbitraryLoads": True}
    assert by_id["com.example.demo.share"]["path"] == "PlugIns/Share.appex"
    assert r["bundles"][0]["bundle_id"] == "com.example.demo"


def test_unreadable_plist_gives_null_ats_with_note(tmp_path, monkeypatch):
    monkeypatch.setattr(inspect_ipa, "run", _fake_run)
    r = inspect_ipa.inspect_app("otool", "plutil", _fake_ipa(tmp_path, "garbage", APPEX_PLIST))
    assert r["ats"] is None
    assert any("Info.plist" in n for n in r["notes"])
    assert r["bundles"][0]["ats"] is None


def test_plist_without_ats_key_is_empty_dict(tmp_path, monkeypatch):
    monkeypatch.setattr(inspect_ipa, "run", _fake_run)
    plain = json.dumps({"CFBundleIdentifier": "com.example.demo", "CFBundleExecutable": "Demo"})
    r = inspect_ipa.inspect_app("otool", "plutil", _fake_ipa(tmp_path, plain, APPEX_PLIST))
    assert r["ats"] == {}
    assert r["notes"] == []


def test_ipa_run_wraps_timeout_and_oserror(monkeypatch):
    def boom_timeout(*a, **k):
        raise subprocess.TimeoutExpired("otool", 1)

    def boom_os(*a, **k):
        raise OSError(2, "No such file")

    monkeypatch.setattr(inspect_ipa.subprocess, "run", boom_timeout)
    with pytest.raises(inspect_ipa.ToolError):
        inspect_ipa.run(["otool", "-hv", "x"])
    monkeypatch.setattr(inspect_ipa.subprocess, "run", boom_os)
    with pytest.raises(inspect_ipa.ToolError):
        inspect_ipa.run(["otool", "-hv", "x"])


def test_ipa_main_reports_tool_error_as_json(tmp_path, monkeypatch, capsys):
    ipa = tmp_path / "a.ipa"
    ipa.write_bytes(b"PK")
    monkeypatch.setattr(inspect_ipa.sys, "platform", "darwin")
    monkeypatch.setattr(inspect_ipa.shutil, "which", lambda t: "/bin/" + t)

    def boom(*a, **k):
        raise subprocess.TimeoutExpired("unzip", 1)

    monkeypatch.setattr(inspect_ipa.subprocess, "run", boom)
    with pytest.raises(SystemExit) as e:
        inspect_ipa.main(["inspect_ipa.py", str(ipa)])
    assert e.value.code == 2
    assert "error" in json.loads(capsys.readouterr().out)


def test_android_linux_sdk_path_searched(tmp_path, monkeypatch):
    tool = tmp_path / "Android" / "Sdk" / "build-tools" / "34.0.0" / "aapt2"
    tool.parent.mkdir(parents=True)
    tool.write_text("")
    monkeypatch.setenv("PATH", "")
    monkeypatch.delenv("ANDROID_HOME", raising=False)
    monkeypatch.delenv("ANDROID_SDK_ROOT", raising=False)
    monkeypatch.setattr(inspect_apk.Path, "home", classmethod(lambda cls: tmp_path))
    assert inspect_apk.find_sdk_tool("aapt2") == str(tool)
