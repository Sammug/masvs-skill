import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "masvs" / "scripts"
DATA = ROOT / "masvs" / "data"
FIX = ROOT / "tests" / "fixtures" / "scan"
sys.path.insert(0, str(SCRIPTS))

import _common  # noqa: E402
import scan_source  # noqa: E402

RULES = json.loads((DATA / "rules.json").read_text())["rules"]
CONTROLS = {c["id"] for c in json.loads((DATA / "controls.json").read_text())}

FAKE_SECRETS = [
    "AKIAIOSFODNN7EXAMPLE",
    "glpat-ABCDEFGHIJKLMNOPQRST",
    "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    "AIzaFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE000",
    "xoxb-000000000000-FAKEFAKEFAKE",
    "-----BEGIN RSA PRIVATE KEY-----",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyXzAwMSJ9.ZmFrZXNpZ25hdHVyZQ",
]


def cli(root, *args):
    p = subprocess.run(
        [sys.executable, str(SCRIPTS / "scan_source.py"), str(root), *args],
        capture_output=True, text=True,
    )
    return p


def run(root, *args):
    p = cli(root, *args)
    assert p.returncode == 0, p.stdout + p.stderr
    return json.loads(p.stdout)


def rules_hit(res, rule=None):
    return sorted({m["rule"] for m in res["matches"]}) if rule is None else [
        m for m in res["matches"] if m["rule"] == rule
    ]


def lines(res, rule, file=None):
    return sorted(
        m["line"] for m in res["matches"]
        if m["rule"] == rule and (file is None or m["file"].endswith(file))
    )


def test_allowbackup_true_matches():
    res = run(FIX / "backup_true", "--stacks", "android")
    (m,) = rules_hit(res, "AND-BACKUP-1")
    assert m["control"] == "MASVS-STORAGE-2"
    assert m["file"] == "app/src/main/AndroidManifest.xml"
    assert m["line"] == 3
    assert m["status"] == "match"
    assert m["owner"] == "app"
    assert 'allowBackup="true"' in m["snippet"]


def test_allowbackup_false_clean():
    res = run(FIX / "backup_false", "--stacks", "android")
    assert res["matches"] == []


def test_manifest_placeholder_unresolved():
    res = run(FIX / "backup_placeholder", "--stacks", "android")
    (m,) = rules_hit(res, "AND-BACKUP-1")
    assert m["status"] == "unresolved"


def test_allowbackup_missing_fires_only_for_manifest_with_application():
    res = run(FIX / "backup_missing", "--stacks", "android")
    hits = rules_hit(res, "AND-BACKUP-2")
    assert [(m["file"], m["line"]) for m in hits] == [("app/src/main/AndroidManifest.xml", 2)]
    assert "<application" in hits[0]["snippet"]
    assert "AND-NET-2" in rules_hit(res)


@pytest.mark.parametrize("rel,owner", [
    (".pub-cache/hosted/pub.dev/path_provider_android-2.2.0/android/src/main/java/io/example/PathProvider.java",
     "path_provider_android"),
    ("lib/main.dart", "app"),
])
def test_owner_attribution(rel, owner):
    res = run(FIX / "owner", "--stacks", "android,flutter", "--include-deps")
    (m,) = [m for m in res["matches"] if m["file"] == rel]
    assert m["owner"] == owner


def test_owner_attribution_other_ecosystems():
    res = run(FIX / "owner", "--stacks", "android,ios,react-native", "--include-deps")
    owners = {m["file"]: m["owner"] for m in res["matches"]}
    assert owners["node_modules/@scope/pkg/index.ts"] == "@scope/pkg"
    assert owners["node_modules/plain-lib/index.ts"] == "plain-lib"
    assert owners["ios/Pods/AFNetworking/Security.m"] == "AFNetworking"
    assert owners["gradle-cache/files-2.1/com.example/some-lib/1.2.3/abc123/Src.java"] == "some-lib"


def test_dependency_dirs_skipped_without_flag():
    res = run(FIX / "owner", "--stacks", "android,flutter,react-native,ios")
    assert {m["file"] for m in res["matches"]} == {
        "lib/main.dart",
        "gradle-cache/files-2.1/com.example/some-lib/1.2.3/abc123/Src.java",
    }


def test_secret_redacted():
    p = cli(FIX / "secrets")
    assert p.returncode == 0
    res = json.loads(p.stdout)
    gl = rules_hit(res, "SECRET-GITLAB-1")
    assert len(gl) == 1 and "glpa…" in gl[0]["snippet"]
    assert "glpat-ABCDEFGHIJKLMNOPQRST" not in p.stdout
    for s in FAKE_SECRETS:
        assert s not in p.stdout
    assert {
        "SECRET-AWS-1", "SECRET-GITLAB-1", "SECRET-GITHUB-1", "SECRET-GOOGLE-1",
        "SECRET-SLACK-1", "SECRET-PEM-1", "SECRET-JWT-1",
    } == set(rules_hit(res))
    assert all(m["control"] in CONTROLS for m in res["matches"])


def test_secrets_not_judged_without_token_shape():
    assert run(FIX / "secrets_none")["matches"] == []


def test_redact_direct():
    assert _common.redact("k=AKIAIOSFODNN7EXAMPLE;") == "k=AKIA…;"
    assert _common.redact("a glpat-ABCDEFGHIJKLMNOPQRST b") == "a glpa… b"
    assert _common.redact("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") == "ghp_…"
    assert _common.redact("github_pat_" + "A" * 30) == "gith…"
    assert _common.redact("AIzaFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE000") == "AIza…"
    assert _common.redact("xoxp-000000000000-FAKEFAKEFAKE") == "xoxp…"
    assert _common.redact("-----BEGIN PRIVATE KEY-----") == "----…"
    assert _common.redact("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyXzAwMSJ9.ZmFrZXNpZ25hdHVyZQ") == "eyJh…"
    assert _common.redact("plain text, nothing to hide") == "plain text, nothing to hide"
    twice = _common.redact("AKIAIOSFODNN7EXAMPLE AKIAIOSFODNN7EXAMPLE")
    assert twice == "AKIA… AKIA…"


def test_redact_applies_to_non_secret_rule_snippets(tmp_path):
    f = tmp_path / "lib" / "a.dart"
    f.parent.mkdir()
    f.write_text("print('glpat-ABCDEFGHIJKLMNOPQRST $token');\n")
    p = cli(tmp_path, "--stacks", "flutter")
    assert "glpat-ABCDEFGHIJKLMNOPQRST" not in p.stdout
    res = json.loads(p.stdout)
    assert "FLT-LOG-1" in rules_hit(res)
    assert all("glpa…" in m["snippet"] for m in res["matches"] if m["rule"] == "FLT-LOG-1")


def test_snippet_trimmed_to_200_after_redaction(tmp_path):
    f = tmp_path / "App.tsx"
    f.write_text("x = '" + "a" * 500 + "'; // glpat-ABCDEFGHIJKLMNOPQRST\n")
    res = run(tmp_path, "--stacks", "react-native")
    (m,) = rules_hit(res, "SECRET-GITLAB-1")
    assert len(m["snippet"]) <= 200
    assert "glpa…" in m["snippet"]
    assert "glpat-ABCDEFGHIJKLMNOPQRST" not in json.dumps(res)


def test_stack_filter():
    res = run(FIX / "ios_bad", "--stacks", "android")
    assert res["matches"] == []
    res = run(FIX / "ios_bad", "--stacks", "ios")
    assert "IOS-ATS-1" in rules_hit(res)


def test_secret_rules_run_for_every_stack(tmp_path):
    (tmp_path / "x.txt").write_text("k = glpat-ABCDEFGHIJKLMNOPQRST\n")
    for stacks in ("android", "ios", "flutter", "react-native", ""):
        args = ["--stacks", stacks] if stacks else []
        assert rules_hit(run(tmp_path, *args), "SECRET-GITLAB-1"), stacks


def test_stacks_detected_when_not_given():
    res = run(FIX / "flutter_bad")
    assert res["stacks"] == ["flutter"]
    assert "FLT-LOG-1" in rules_hit(res)
    assert "AND-BACKUP-2" not in rules_hit(res)


def test_every_rule_control_exists():
    for r in RULES:
        assert r["control"] in CONTROLS, r["id"]


def test_rule_schema():
    seen = set()
    for r in RULES:
        assert r["id"] not in seen
        seen.add(r["id"])
        assert r["kind"] in {"smell", "secret", "config"}
        assert r["stacks"] and set(r["stacks"]) <= {"android", "ios", "flutter", "react-native", "*"}
        assert r["files"] and r["message"]
        if not r["pattern"].startswith("@secret:"):
            re.compile(r["pattern"])
        if r.get("unresolved_pattern"):
            re.compile(r["unresolved_pattern"])
        if r.get("absent"):
            assert r["kind"] == "config"
        if r.get("exists"):
            assert r["kind"] == "config" and r["pattern"] == "" and not r.get("absent")
        if r["kind"] == "secret":
            assert r["pattern"][len("@secret:"):] in _common.SECRET_PATTERNS
    assert len(RULES) == len(seen)


def test_every_stack_has_rules_in_every_applicable_group():
    by_stack = {s: {r["control"].split("-")[1] for r in RULES if s in r["stacks"]}
                for s in ("android", "ios", "flutter", "react-native")}
    assert {"STORAGE", "CRYPTO", "NETWORK", "PLATFORM", "CODE"} <= by_stack["android"]
    assert {"STORAGE", "NETWORK"} <= by_stack["ios"]
    assert {"STORAGE", "NETWORK", "PRIVACY"} <= by_stack["flutter"]
    assert {"STORAGE", "PLATFORM"} <= by_stack["react-native"]


EXPECTED_ANDROID_BAD = {
    "AND-NET-1", "AND-NET-3", "AND-IPC-1", "AND-STORAGE-1", "AND-STORAGE-2", "AND-STORAGE-3",
    "AND-CRYPTO-1", "AND-CRYPTO-2", "AND-CRYPTO-3", "AND-TLS-1", "AND-TLS-2",
    "AND-WEBVIEW-1", "AND-WEBVIEW-2", "AND-WEBVIEW-3", "AND-LOG-1", "AND-SDK-1",
}


def test_android_bad_fires_every_rule():
    res = run(FIX / "android_bad", "--stacks", "android")
    assert set(rules_hit(res)) == EXPECTED_ANDROID_BAD


def test_android_bad_line_precision():
    res = run(FIX / "android_bad", "--stacks", "android")
    assert lines(res, "AND-IPC-1") == [13, 14]
    assert lines(res, "AND-CRYPTO-1", "Bad.kt") == [7, 9]
    assert lines(res, "AND-CRYPTO-2") == [8]
    assert lines(res, "AND-CRYPTO-3") == [10, 11]
    assert lines(res, "AND-LOG-1") == [14, 15]
    assert lines(res, "AND-STORAGE-1") == [5]
    assert lines(res, "AND-STORAGE-3") == [16]
    assert lines(res, "AND-TLS-1", "Bad.kt") == [22]
    assert lines(res, "AND-TLS-2", "Bad.kt") == [25]
    ipc_files = {m["file"] for m in rules_hit(res, "AND-IPC-1")}
    assert ipc_files == {"app/src/main/AndroidManifest.xml"}


def test_android_legacy_java_rules():
    res = run(FIX / "android_bad", "--stacks", "android")
    legacy = {m["rule"] for m in res["matches"] if m["file"].endswith("Legacy.java")}
    assert {"AND-CRYPTO-1", "AND-TLS-1", "AND-TLS-2", "AND-WEBVIEW-3"} <= legacy


def test_android_clean_has_no_matches():
    res = run(FIX / "android_clean", "--stacks", "android")
    assert res["matches"] == []


@pytest.mark.parametrize("sub,expected", [
    ("a", "match"), ("b", "unresolved"), ("c", "match"), ("d", None),
])
def test_minsdk_variants(sub, expected):
    res = run(FIX / "android_gradle_variants" / sub, "--stacks", "android")
    hits = rules_hit(res, "AND-SDK-1")
    if expected is None:
        assert hits == []
    else:
        assert [m["status"] for m in hits] == [expected]


def test_ios_bad_fires_every_rule():
    res = run(FIX / "ios_bad", "--stacks", "ios")
    assert set(rules_hit(res)) == {
        "IOS-ATS-1", "IOS-KEYCHAIN-1", "IOS-STORAGE-1", "IOS-PASTE-1", "IOS-LOG-1",
        "IOS-CRYPTO-1", "IOS-HARDEN-1",
    }
    assert lines(res, "IOS-STORAGE-1") == [2, 4, 5]
    assert lines(res, "IOS-LOG-1") == [3, 8, 9]
    assert lines(res, "IOS-PASTE-1") == [7]


def test_ios_clean_has_no_matches():
    res = run(FIX / "ios_clean", "--stacks", "ios")
    assert res["matches"] == []


def test_flutter_bad_fires_every_rule():
    res = run(FIX / "flutter_bad", "--stacks", "flutter")
    assert set(rules_hit(res)) == {
        "FLT-STORAGE-1", "FLT-STORAGE-2", "FLT-TLS-1", "FLT-LOG-1",
        "FLT-TELEMETRY-1", "FLT-TELEMETRY-2", "FLT-TELEMETRY-3", "FLT-CRYPTO-1",
        "FLT-DEP-1", "FLT-TELEMETRY-4", "FLT-LOG-2",
    }
    assert lines(res, "FLT-STORAGE-1") == [4, 5, 6]
    assert lines(res, "FLT-LOG-1") == [7, 8, 9]
    assert lines(res, "FLT-TLS-1") == [12, 14]
    assert lines(res, "FLT-STORAGE-2") == [10]
    assert lines(res, "FLT-TELEMETRY-2") == [22, 23]
    assert res["skipped_rules"] == []


def test_flutter_clean_has_no_matches():
    res = run(FIX / "flutter_clean", "--stacks", "flutter")
    assert res["matches"] == []


def test_flutter_secure_storage_new_major_not_flagged():
    res = run(FIX / "flutter_new_storage", "--stacks", "flutter")
    assert res["matches"] == []
    assert res["skipped_rules"] == []


def test_flutter_secure_storage_missing_lock_skipped():
    res = run(FIX / "flutter_nolock", "--stacks", "flutter")
    assert res["matches"] == []
    assert [s["rule"] for s in res["skipped_rules"]] == ["FLT-STORAGE-2"]
    assert "pubspec.lock" in res["skipped_rules"][0]["reason"]


def test_rn_bad_fires_every_rule():
    res = run(FIX / "rn_bad", "--stacks", "react-native")
    assert set(rules_hit(res)) == {"RN-STORAGE-1", "RN-WEBVIEW-1", "RN-LOG-1", "RN-DEP-1"}
    assert lines(res, "RN-STORAGE-1") == [4, 5]
    assert lines(res, "RN-LOG-1") == [6, 7]


def test_rn_clean_has_no_matches():
    res = run(FIX / "rn_clean", "--stacks", "react-native")
    assert res["matches"] == []


def test_matches_sorted_and_deduped():
    res = run(FIX / "android_bad", "--stacks", "android")
    keys = [(m["file"], m["line"], m["rule"]) for m in res["matches"]]
    assert keys == sorted(keys)
    assert len(keys) == len(set(keys))


def test_match_shape():
    res = run(FIX / "flutter_bad", "--stacks", "flutter")
    for m in res["matches"]:
        assert set(m) == {"rule", "control", "file", "line", "snippet", "owner", "status"}
        assert m["status"] in {"match", "unresolved"}
        assert len(m["snippet"]) <= 200


def test_bad_root_exits_2():
    p = cli(FIX / "does-not-exist")
    assert p.returncode == 2
    assert "error" in json.loads(p.stdout)
    assert cli(FIX / "backup_true" / "app" / "src" / "main" / "AndroidManifest.xml").returncode == 2


def test_unknown_stack_exits_2():
    p = cli(FIX / "backup_true", "--stacks", "symbian")
    assert p.returncode == 2
    assert "error" in json.loads(p.stdout)


def test_binary_and_oversized_files_skipped_silently(tmp_path):
    (tmp_path / "blob.kt").write_bytes(b"\x00\x01Log.d(TAG, \"x\" + token)\n")
    (tmp_path / "big.kt").write_text("Log.d(TAG, \"x\" + token)\n" + "a" * 2_100_000)
    (tmp_path / "ok.kt").write_text("Log.d(TAG, \"x\" + token)\n")
    res = run(tmp_path, "--stacks", "android")
    assert [m["file"] for m in res["matches"]] == ["ok.kt"]


def test_debug_source_set_cleartext_not_flagged():
    res = run(FIX / "android_debug_cleartext", "--stacks", "android")
    assert "AND-NET-1" not in rules_hit(res)


def test_encrypted_shared_preferences_file_not_flagged(tmp_path):
    (tmp_path / "A.kt").write_text(
        "val p = EncryptedSharedPreferences.create(ctx, \"f\", key, a, b)\n"
        "p.edit().putString(\"auth_token\", t).apply()\n"
    )
    assert run(tmp_path, "--stacks", "android")["matches"] == []


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file modes")
def test_unreadable_file_skipped(tmp_path):
    f = tmp_path / "locked.kt"
    f.write_text("Log.d(TAG, \"x\" + token)\n")
    f.chmod(0)
    try:
        res = run(tmp_path, "--stacks", "android")
    finally:
        f.chmod(0o644)
    assert res["matches"] == []


PEM_JSON = (
    '{"type": "service_account", "private_key": "-----BEGIN PRIVATE KEY-----\\n'
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\\n"
    'ZmFrZWZha2VmYWtlZmFrZWZha2U=\\n-----END PRIVATE KEY-----\\n", "client_email": "x@example.invalid"}\n'
)


def test_redact_one_line_pem_consumes_body():
    out = _common.redact(PEM_JSON)
    assert "MIIEvQ" not in out and "BEGIN" not in out and "END PRIVATE" not in out
    assert out.startswith('{"type": "service_account", "private_key": "----…')
    assert out.endswith('", "client_email": "x@example.invalid"}\n')


def test_one_line_pem_key_body_not_in_scanner_output(tmp_path):
    (tmp_path / "sa.json").write_text(PEM_JSON)
    p = cli(tmp_path, "--stacks", "android")
    assert p.returncode == 0
    res = json.loads(p.stdout)
    (m,) = rules_hit(res, "SECRET-PEM-1")
    assert "----…" in m["snippet"]
    assert "MIIEvQ" not in p.stdout
    assert not re.search(r"[A-Za-z0-9+/]{20,}", p.stdout)


def test_redact_literals_direct():
    assert _common.redact_literals("p.setString('auth_token', 'sk_live_51HxyzFAKEFAKE00')") == \
        "p.setString('auth_token', 'sk_l…')"
    assert _common.redact_literals('k = "Zm9vYmFyYmF6cXV4MTIz"') == 'k = "Zm9v…"'
    for untouched in (
        "'auth_token'", "'loading'", '"short1"', "'abcdefghijklmnopqrstuvwxyz'",
        "'network_security_config_value'", "'1234567890123456789'", "'has space 1234567890123456'",
        "'https://example.invalid/path1'",
    ):
        assert _common.redact_literals(untouched) == untouched


def test_literal_secret_in_smell_snippet_redacted(tmp_path):
    f = tmp_path / "lib" / "a.dart"
    f.parent.mkdir()
    f.write_text("void f(SharedPreferences p) { p.setString('auth_token', 'sk_live_51HxyzFAKEFAKE00'); }\n")
    p = cli(tmp_path, "--stacks", "flutter")
    assert "sk_live_51HxyzFAKEFAKE00" not in p.stdout
    (m,) = rules_hit(json.loads(p.stdout), "FLT-STORAGE-1")
    assert "'auth_token'" in m["snippet"] and "'sk_l…'" in m["snippet"]


def test_plain_literals_untouched_in_snippets(tmp_path):
    f = tmp_path / "lib" / "a.dart"
    f.parent.mkdir()
    f.write_text("void f(SharedPreferences p) { p.setString('auth_token', 'loading'); }\n")
    (m,) = rules_hit(run(tmp_path, "--stacks", "flutter"), "FLT-STORAGE-1")
    assert m["snippet"].endswith("p.setString('auth_token', 'loading'); }")


def write(root, files):
    for rel, body in files.items():
        f = root / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(body if isinstance(body, bytes) else body.encode())
    return root


def test_transitive_sqlite_lock_entries_flagged(tmp_path):
    lock = "packages:\n" + "".join(
        f"  {n}:\n    dependency: transitive\n    source: hosted\n    version: \"2.0.0\"\n"
        for n in ("sqflite", "sqflite_common", "sqflite_darwin", "sqflite_common_ffi", "path")
    )
    write(tmp_path, {"pubspec.lock": lock})
    res = run(tmp_path, "--stacks", "flutter")
    hits = rules_hit(res, "FLT-DEP-1")
    assert [m["snippet"] for m in hits] == ["sqflite:", "sqflite_common:", "sqflite_darwin:"]
    assert {m["control"] for m in hits} == {"MASVS-CODE-3"}


def test_transitive_sqlite_absent_not_flagged():
    res = run(FIX / "flutter_clean", "--stacks", "flutter")
    assert rules_hit(res, "FLT-DEP-1") == []


def test_rn_sqlite_dependency_in_package_json_only():
    assert lines(run(FIX / "rn_bad", "--stacks", "react-native"), "RN-DEP-1") == [1]
    assert rules_hit(run(FIX / "rn_clean", "--stacks", "react-native"), "RN-DEP-1") == []


def test_stack_protector_only_in_comment_fires(tmp_path):
    write(tmp_path, {"Podfile": "# OTHER_CFLAGS = '-fstack-protector-all'\n  # -fstack-protector\ntarget 'Runner' do\nend\n"})
    res = run(tmp_path, "--stacks", "ios")
    assert lines(res, "IOS-HARDEN-1") == [1]
    (m,) = rules_hit(res, "IOS-HARDEN-1")
    assert m["snippet"] == "(pattern absent from file)"


def test_stack_protector_in_post_install_clean():
    res = run(FIX / "ios_clean", "--stacks", "ios")
    assert rules_hit(res, "IOS-HARDEN-1") == []


def test_stack_protector_trailing_comment_only_fires(tmp_path):
    write(tmp_path, {"Podfile": "config.build_settings['X'] = '1' # add -fstack-protector later\n"})
    assert lines(run(tmp_path, "--stacks", "ios"), "IOS-HARDEN-1") == [1]


def test_sentry_init_without_before_send_flagged():
    res = run(FIX / "flutter_bad", "--stacks", "flutter")
    assert lines(res, "FLT-TELEMETRY-4") == [28]


def test_sentry_init_with_before_send_not_flagged():
    res = run(FIX / "flutter_clean", "--stacks", "flutter")
    assert rules_hit(res, "FLT-TELEMETRY-4") == []


def test_sentry_before_send_in_comment_only_still_flagged(tmp_path):
    write(tmp_path, {"lib/a.dart": "// TODO beforeSend\nvoid f() { Sentry.init((o) {}); }\n"})
    assert lines(run(tmp_path, "--stacks", "flutter"), "FLT-TELEMETRY-4") == [2]


def test_sentry_init_commented_out_not_flagged(tmp_path):
    write(tmp_path, {"lib/a.dart": "// await SentryFlutter.init((o) {});\n"})
    assert rules_hit(run(tmp_path, "--stacks", "flutter"), "FLT-TELEMETRY-4") == []


def test_log_interceptor_bodies_flagged_unguarded():
    res = run(FIX / "flutter_bad", "--stacks", "flutter")
    assert lines(res, "FLT-LOG-2") == [31]


def test_log_interceptor_guarded_by_debug_mode_not_flagged():
    res = run(FIX / "flutter_clean", "--stacks", "flutter")
    assert rules_hit(res, "FLT-LOG-2") == []


def test_log_interceptor_variants(tmp_path):
    write(tmp_path, {
        "lib/multi.dart": "final i = LogInterceptor(\n  request: true,\n  responseBody: true,\n);\n",
        "lib/headers.dart": "final i = LogInterceptor(requestHeader: true, requestBody: false);\n",
        "lib/default.dart": "final i = LogInterceptor();\n",
        "lib/release.dart": "final i = kReleaseMode ? null : LogInterceptor(responseBody: true);\n",
    })
    hits = rules_hit(run(tmp_path, "--stacks", "flutter"), "FLT-LOG-2")
    assert [m["file"] for m in hits] == ["lib/multi.dart"]


@pytest.mark.parametrize("name", [
    "upload.jks", "release.keystore", "cert.p12", "cert.pfx", "keystore_base64.txt",
    "release-keystore.base64", "android/key.properties",
])
def test_signing_material_by_name_flagged_without_reading(tmp_path, name):
    write(tmp_path, {name: b"\x00\x01 sup3rS3cretStorePassw0rd \x00"})
    res = run(tmp_path, "--stacks", "android")
    (m,) = [m for m in res["matches"] if m["rule"].startswith(("SECRET-KEYSTORE", "SECRET-KEYPROPS"))]
    assert m["control"] == "MASVS-CRYPTO-2"
    assert m["line"] == 1
    assert m["snippet"] == f"file present: {Path(name).name}"
    assert "sup3rS3cret" not in json.dumps(res)


def test_signing_material_text_content_never_leaks(tmp_path):
    write(tmp_path, {"android/key.properties": "storePassword=hunter2hunter2\nkeyAlias=upload\n"})
    out = cli(tmp_path, "--stacks", "android").stdout
    assert "hunter2" not in out and "SECRET-KEYPROPS-1" in out


def test_debug_keystore_and_unrelated_files_not_flagged(tmp_path):
    write(tmp_path, {
        "android/app/debug.keystore": b"\x00",
        "docs/keystore.md": "how to make a keystore",
        "lib/key_properties.dart": "class K {}",
    })
    res = run(tmp_path, "--stacks", "android")
    assert not [m for m in res["matches"] if m["rule"].startswith("SECRET-KEY")]


def test_service_account_json_flagged_without_key_material(tmp_path):
    body = json.dumps({"type": "service_account", "project_id": "p", "private_key_id": "abcd1234efgh5678",
                       "private_key": "-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\\n-----END PRIVATE KEY-----\\n"},
                      indent=2)
    write(tmp_path, {"deploy/sa.json": body, "deploy/other.json": '{"type": "authorized_user"}'})
    res = run(tmp_path, "--stacks", "android")
    (m,) = rules_hit(res, "SECRET-SA-1")
    assert (m["file"], m["line"], m["control"]) == ("deploy/sa.json", 2, "MASVS-CRYPTO-2")
    assert "MIIEvQ" not in json.dumps(res)


def _git(root, *args):
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True)


@pytest.mark.skipif(not _git(".", "--version").returncode == 0, reason="git not installed")
def test_gitignored_signing_material_skipped(tmp_path):
    write(tmp_path, {".gitignore": "key.properties\n", "key.properties": "x=1\n", "upload.jks": b"\x00"})
    assert _git(tmp_path, "init", "-q").returncode == 0
    res = run(tmp_path, "--stacks", "android")
    assert [m["rule"] for m in res["matches"]] == ["SECRET-KEYSTORE-1"]


@pytest.mark.skipif(not _git(".", "--version").returncode == 0, reason="git not installed")
def test_tracked_file_flagged_even_if_pattern_ignored(tmp_path):
    write(tmp_path, {"key.properties": "x=1\n"})
    assert _git(tmp_path, "init", "-q").returncode == 0
    _git(tmp_path, "add", "key.properties")
    write(tmp_path, {".gitignore": "key.properties\n"})
    res = run(tmp_path, "--stacks", "android")
    assert [m["rule"] for m in res["matches"]] == ["SECRET-KEYPROPS-1"]


def test_sentry_init_delegating_to_configurator_not_flagged(tmp_path):
    write(tmp_path, {"lib/a.dart": "await SentryFlutter.init(\n  (options) => configureSentry(options),\n);\nawait Sentry.init(configureSentry);\n"})
    assert rules_hit(run(tmp_path, "--stacks", "flutter"), "FLT-TELEMETRY-4") == []


def test_flutter_secure_storage_explicit_false_still_flagged():
    res = run(FIX / "flutter_storage_false", "--stacks", "flutter")
    assert lines(res, "FLT-STORAGE-2") == [1]


def test_redact_more_token_formats():
    cases = {
        "ASIAIOSFODNN7EXAMPLE": "ASIA…",
        "ghs_" + "A1b2" * 9: "ghs_…",
        "ghu_" + "A1b2" * 9: "ghu_…",
        "ghr_" + "A1b2" * 9: "ghr_…",
        "sk_live_" + "A1b2C3d4" * 3: "sk_l…",
        "rk_live_" + "A1b2C3d4" * 3: "rk_l…",
        "sk-" + "A1b2C3d4E5" * 3: "sk-A…",
        "sk-proj-" + "A1b2C3d4E5" * 3: "sk-p…",
    }
    for raw, expected in cases.items():
        assert _common.redact(f"x={raw};") == f"x={expected};", raw
    assert _common.redact("sk-short") == "sk-short"
    assert _common.redact("task-force-alpha-bravo-charlie") == "task-force-alpha-bravo-charlie"
