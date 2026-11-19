# Using the masvs skill

Ways to run the skill, with examples you can copy. For script options and output keys, see [REFERENCE.md](REFERENCE.md). For problems, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

- [Choose how to run it](#choose-how-to-run-it)
- [Write a good prompt](#write-a-good-prompt)
- [Audit](#audit)
- [Remediate](#remediate)
- [Checklist and questions](#checklist-and-questions)
- [Headless runs](#headless-runs)
- [Run the scripts directly](#run-the-scripts-directly)
- [CI: fail the build on committed secrets](#ci-fail-the-build-on-committed-secrets)
- [The fix, build, re-verify, close loop](#the-fix-build-re-verify-close-loop)
- [What the skill will refuse to do](#what-the-skill-will-refuse-to-do)

## Choose how to run it

| Way | How | Best for | What you get |
|---|---|---|---|
| Plain language | Ask in Claude Code; the skill loads when you mention MASVS, MASWE, a pentest, VAPT or a mobile security audit | Day-to-day work | The full skill: scripts, playbooks, evidence rules, report |
| Slash command | `/masvs:masvs <request>` (`/masvs` with a zip install) | Making sure the skill is used | The same |
| Headless | `claude -p "<request>" --allowedTools ...` | Scheduled or scripted audits | The same, with no prompts; files are written to `.masvs/` |
| Scripts directly | `python3 skills/masvs/scripts/<name>.py ...` | CI gates, quick checks, debugging a rule | Raw JSON only: scan **matches**, not findings, with no severity or status |
| Claude apps with an uploaded skill zip | Upload `masvs-<version>.zip` as a skill | Questions, checklists, mapping findings to MASVS/MASWE | Partial: there is no Android SDK or Xcode there, so APK/IPA checks come back as `Not run` |

## Write a good prompt

A good prompt says three things: **the mode** (audit, remediate or checklist), **what to look at** (the repo, a built APK/IPA, a flavor, the auditor's sheet) and **what you want back** (a report, fixes, responses, a checklist).

| Weak | Strong | Why |
|---|---|---|
| "Is my app secure?" | "Run a MASVS audit of this app before the pentest. The release APK is at `build/app/outputs/flutter-apk/app-release.apk`. Write the report and an xlsx." | Names the mode, gives the built artifact (so build-only checks can run) and the output. |
| "Fix the pentest issues." | "Here is the VAPT sheet: `docs/security/vapt-round1.xlsx`. For each finding, map it to MASVS and MASWE, decide fix / already mitigated / false positive with evidence, fix what's real and fill in the response columns." | Gives the input file and the classification you expect. |
| "Mark everything fixed." | "We changed the manifest for findings 3 and 5. Re-verify them on the new APK at `build/app-release.apk` and update their status." | Asks for verification, which is the only way a row becomes `Fixed`. |
| "Biometrics checklist." | "I'm adding biometric login to our Flutter app on Android and iOS. Give me the MASVS/MASWE checklist with the fix pattern and the test to show an auditor." | Names the stack, platforms and what each item should contain. |

## Audit

### Source only

```text
Run a MASVS audit of this repo. There's no build yet: tell me which checks can't run without an APK or IPA.
```

Checks that need a build (merged manifest, `debuggable`, exported components, permissions, binary protections, release flags) are recorded as `Not run` with the reason "no APK/IPA".

### Source plus APK and IPA

Build the release artifacts first:

```bash
# Flutter
flutter build apk --release                  # build/app/outputs/flutter-apk/app-release.apk
flutter build ipa --release                  # build/ios/ipa/<App>.ipa (macOS)

# Native Android
./gradlew assembleRelease                    # app/build/outputs/apk/release/app-release.apk

# React Native
cd android && ./gradlew assembleRelease      # android/app/build/outputs/apk/release/app-release.apk
```

Then:

```text
Run a MASVS audit of this app. The release APK is at build/app/outputs/flutter-apk/app-release.apk
and the IPA is at build/ios/ipa/ExampleApp.ipa. Write the report and an xlsx.
```

### One platform or flavor

```text
/masvs:masvs audit — Android only, prod flavor. The APK is at build/app/outputs/flutter-apk/app-prod-release.apk.
Resolve manifest placeholders for the prod flavor and note anything that differs from dev.
```

### Flutter with native extensions

```text
Audit this Flutter app for MASVS, including the iOS Share Extension in ios/ShareExtension and the
Android home-screen widget. Rate each target like the main app.
```

Even if you ask for "just the Dart code", the skill checks native code in the repo too and says so in one line: pentesters test the whole bundle.

### One MASVS group

```text
MASVS-NETWORK only: check cleartext settings, ATS and the network security config, and check the
pins in android/app/src/main/res/xml/network_security_config.xml against the live api.example.invalid.
```

The live pin check runs `check_pins.py --nsc <file> --host api.example.invalid`, which connects to that host.

### Custom output folder

```text
Run a MASVS audit and write findings.json and the report to security/reports/2026-q4/ instead of .masvs/.
```

## Remediate

### From an auditor's spreadsheet

```text
Here is the VAPT report: docs/security/vapt-round1.xlsx. For each finding, map it to a MASVS control
and MASWE weakness, decide fix / already mitigated / false positive with evidence, fix what is real,
and fill in the response columns.
```

### From pasted findings

```text
Respond to these pentest findings for our React Native app:

F-01 Application data can be backed up (android:allowBackup=true)
F-02 Sensitive information in application logs
F-03 SSL pinning not implemented

Map each to MASVS and MASWE, reproduce it, and draft the auditor response.
```

If there's no `findings.json`, the skill creates one from the auditor's rows, with `ticket` holding the auditor's ID (`F-01`).

### One finding

```text
The pentester says "Weak Cryptographic Implementation: AES-CBC with PKCS7 padding". Which MASWE
weakness is this, is it real in our code or in a plugin, and what should we reply?
```

### Proving a plugin false positive

```text
The auditor flagged WRITE_EXTERNAL_STORAGE and an external-storage call in the APK. I think it comes
from a plugin, not our code. Prove it either way.
```

The skill names the owning package (`scan_source.py --include-deps`, `pubspec.lock` or Gradle dependencies), shows that app code doesn't reach it and checks the permission side with `inspect_apk.py`. Without the APK the row is `False positive` with `evidence_kind: inferred`, and the response names the artifact check that will confirm it.

### A fix that changes UX or the backend

```text
The auditor wants us to force login on every app launch. What's the real weakness and what are our options?
```

Fixes that change UX (forced re-login, removing biometrics, extra prompts) or need backend work (pin rotation, token lifetime, a revoke endpoint) are proposed, not applied. The skill offers the UX-neutral fix first, drafts an auditor response that explains the compensating controls, and keeps the row `Open` until you sign off.

## Checklist and questions

```text
I'm adding biometric login on Flutter. Give me the MASVS/MASWE checklist for Android and iOS,
with the fix pattern and the test to show an auditor.
```

```text
We're adding a WebView to our React Native app to show help articles. What MASVS/MASWE checks apply?
```

```text
We're adding deep links to our native Android app. Checklist, please.
```

```text
I'm storing a refresh token in the iOS Keychain. Which accessibility class should I use, and what will the auditor test?
```

Questions:

```text
Explain MASWE-0006 for a React Native app and show me how to check it in our build.
Which MASWE weaknesses fall under MASVS-NETWORK-1, and which ones do we fail?
Which MASTG tests apply to MASVS-STORAGE-2 for a Flutter app?
```

## Headless runs

Run an audit without an interactive session, for example on a schedule:

```bash
claude -p "Run a MASVS audit of this repo and write the report to .masvs/" \
  --allowedTools "Bash(python3:*)" "Bash(git ls-files:*)" "Bash(git log:*)" Read Write Glob Grep
```

- Install the plugin first, from a shell (`claude plugin install masvs@masvs-skill`) or with the team settings snippet in the [README](../README.md#installation). `/plugin` commands don't work in `-p` mode.
- Leave `Edit` out of `--allowedTools` for audit-only runs, so the run can write the report but can't change your code.
- Add `--output-format json` to get the final message and run metadata as JSON.

## Run the scripts directly

The scripts work without Claude. They print JSON and use only the Python standard library. Their output is raw: scan **matches**, not findings, with no severity or status. The examples below run against fixtures in this repo, from the repo root.

```bash
S=skills/masvs/scripts
```

### detect_stack.py

```bash
python3 $S/detect_stack.py tests/fixtures/stacks/mono
```

```json
{
  "stacks": [
    "android",
    "flutter",
    "ios"
  ],
  "android_manifests": [
    "android-lib/src/main/AndroidManifest.xml"
  ],
  "ios_plists": [
    "ios/Runner/Info.plist",
    "ios/ShareExt/Info.plist"
  ],
  "dependency_files": [
    "android-lib/build.gradle",
    "pubspec.yaml"
  ]
}
```

### scan_source.py

```bash
python3 $S/scan_source.py tests/fixtures/scan/flutter_bad > scan.json
jq '.matches[] | select(.rule == "FLT-TLS-1")' scan.json
```

```json
{
  "rule": "FLT-TLS-1",
  "control": "MASVS-NETWORK-1",
  "maswe": [
    "MASWE-0027"
  ],
  "file": "lib/bad.dart",
  "line": 12,
  "snippet": "..badCertificateCallback = (X509Certificate cert, String host, int port) => true;",
  "owner": "app",
  "status": "match"
}
{
  "rule": "FLT-TLS-1",
  "control": "MASVS-NETWORK-1",
  "maswe": [
    "MASWE-0027"
  ],
  "file": "lib/bad.dart",
  "line": 14,
  "snippet": "..badCertificateCallback = (_, __, ___) {",
  "owner": "app",
  "status": "match"
}
```

Secrets are redacted to their first 4 characters:

```bash
python3 $S/scan_source.py tests/fixtures/scan/secrets | jq -r '.matches[] | "\(.rule)\t\(.snippet)"'
```

```text
SECRET-AWS-1	aws = AKIA…
SECRET-GITLAB-1	gitlab = glpa…
SECRET-GITHUB-1	github = ghp_…
SECRET-GOOGLE-1	google = AIza…
SECRET-SLACK-1	slack = xoxb…
SECRET-PEM-1	----…
SECRET-JWT-1	jwt = eyJh…
```

Options:

```bash
python3 $S/scan_source.py <root> --stacks android,ios     # override detected stacks
python3 $S/scan_source.py <root> --include-deps           # also scan node_modules, Pods, vendor, .pub-cache
```

More `jq` one-liners:

```bash
# Match count per rule
jq -r '.matches | group_by(.rule) | map("\(.[0].rule)\t\(length)") | .[]' scan.json

# Matches for one control, as file:line
jq -r '.matches[] | select(.control == "MASVS-NETWORK-1") | "\(.file):\(.line)  \(.rule)"' scan.json

# Third-party packages that matched (with --include-deps)
jq -r '.matches[] | select(.owner != "app") | .owner' scan.json | sort -u

# Rules that couldn't run, and why
jq '.skipped_rules' scan.json
```

### inspect_apk.py and inspect_ipa.py

```bash
python3 $S/inspect_apk.py build/app/outputs/flutter-apk/app-release.apk
python3 $S/inspect_ipa.py build/ios/ipa/ExampleApp.ipa      # macOS only

python3 $S/inspect_apk.py app-release.apk | jq '{allow_backup, uses_cleartext, debuggable, exported}'
```

Without `aapt2`/`apkanalyzer` (or off macOS for IPAs) they print `{"skipped": "<reason>"}` and exit 0. The output keys are listed in [REFERENCE.md](REFERENCE.md#inspect_apkpy).

### check_pins.py

Parse a network security config (`--nsc`). `--today` fixes the date used for `days_left`:

```bash
python3 $S/check_pins.py \
  --nsc evals/fixtures/6-pre-pentest-no-artifacts/android/app/src/main/res/xml/network_security_config.xml \
  --today 2026-11-19
```

```json
{
  "domains": [
    {
      "domain": "api.example.invalid",
      "include_subdomains": true,
      "pins": [
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
      ],
      "expiration": "2026-06-30",
      "days_left": -142,
      "backup_pin": true,
      "pinned_level": "unknown",
      "matched_levels": [],
      "live_match": null
    }
  ]
}
```

A negative `days_left` means the pin-set has expired and Android no longer enforces it.

Compare the pins with a live host (`--host`, connects to the host, needs `openssl`):

```bash
python3 $S/check_pins.py --nsc network_security_config.xml --host api.example.invalid --port 443
```

`--host` only fills `live_match` for the `<domain>` entry whose text is exactly the host you pass. See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for subdomains.

Compare with a saved PEM chain (`--chain`, leaf first, no network). This output comes from a throwaway leaf → intermediate → root chain generated with `openssl`, with the intermediate's SPKI hash pinned:

```bash
python3 $S/check_pins.py --nsc nsc.xml --chain chain.pem --today 2026-11-19
```

```json
{
  "domains": [
    {
      "domain": "api.example.invalid",
      "include_subdomains": true,
      "pins": [
        "LLxj3Q1ziWwjttfGAAoiHL1kQqzY+Y2ZWn4JeTzxZp4=",
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
      ],
      "expiration": "2027-06-30",
      "days_left": 223,
      "backup_pin": true,
      "pinned_level": "intermediate",
      "matched_levels": [
        "intermediate"
      ],
      "live_match": true
    }
  ]
}
```

To save a server's chain for `--chain`:

```bash
openssl s_client -connect api.example.invalid:443 -servername api.example.invalid -showcerts </dev/null > chain.pem
```

### make_report.py

```bash
python3 $S/make_report.py docs/examples/findings.example.json --out /tmp/masvs-example
```

```json
{"written": ["/tmp/masvs-example/report.md", "/tmp/masvs-example/report.xlsx"]}
```

With `openpyxl` missing, the second file is `report.csv`. The rendered example is [examples/report.example.md](examples/report.example.md).

## CI: fail the build on committed secrets

This GitHub Actions job runs the scanner on every push and pull request, uploads the JSON, and fails only on `SECRET-*` matches. Other matches are left for a human or the skill to triage. Pin the skill to a release tag so rule changes don't break your build unexpectedly.

```yaml
name: masvs-scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Get the masvs skill
        run: git clone --depth 1 --branch v0.3.1 https://github.com/Sammug/masvs-skill.git "$RUNNER_TEMP/masvs-skill"

      - name: Scan source
        env:
          SKILL: ${{ runner.temp }}/masvs-skill/skills/masvs
          APP: .
        run: |
          python3 "$SKILL/scripts/scan_source.py" "$APP" > masvs-scan.json
          python3 - masvs-scan.json <<'PY'
          import json, sys
          data = json.load(open(sys.argv[1]))
          if "error" in data:
              print(f"::error::scan_source failed: {data['error']}")
              sys.exit(2)
          secrets = [m for m in data["matches"] if m["rule"].startswith("SECRET-")]
          for m in secrets:
              print(f"::error file={m['file']},line={m['line']}::{m['rule']} ({m['control']}): {m['snippet']}")
          print(f"{len(data['matches'])} matches, {len(secrets)} secret matches")
          sys.exit(1 if secrets else 0)
          PY

      - name: Upload scan results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: masvs-scan
          path: masvs-scan.json
```

Against `tests/fixtures/scan/secrets` the gate prints, and exits 1:

```text
::error file=config.txt,line=1::SECRET-AWS-1 (MASVS-STORAGE-2): aws = AKIA…
::error file=config.txt,line=2::SECRET-GITLAB-1 (MASVS-STORAGE-2): gitlab = glpa…
::error file=config.txt,line=3::SECRET-GITHUB-1 (MASVS-STORAGE-2): github = ghp_…
::error file=config.txt,line=4::SECRET-GOOGLE-1 (MASVS-STORAGE-2): google = AIza…
::error file=config.txt,line=5::SECRET-SLACK-1 (MASVS-STORAGE-2): slack = xoxb…
::error file=config.txt,line=6::SECRET-PEM-1 (MASVS-CRYPTO-2): ----…
::error file=config.txt,line=7::SECRET-JWT-1 (MASVS-STORAGE-2): jwt = eyJh…
7 matches, 7 secret matches
```

Against `tests/fixtures/scan/secrets_none` it prints `0 matches, 0 secret matches` and exits 0.

Snippets are already redacted, so the log never shows a full secret. The uploaded `masvs-scan.json` lists file paths and rule IDs. Treat it as security-sensitive and keep the artifact's retention short.

If a secret is found, revoke and rotate it. Deleting the file, or removing it from git history, doesn't un-leak it.

## The fix, build, re-verify, close loop

1. **Fix.** The skill applies config-only or small code fixes that need no backend or UX change, and proposes the rest.
2. **Mark it pending.** The row stays `Open`, with the response "Change applied in `<file>`; pending verification in the next build" and the exact command that will verify it.
3. **Build** a release APK or IPA that includes the change.
4. **Re-verify** with the command that reproduced the finding, for example:

   ```text
   Re-verify findings EXW-101 and EXW-104 on the new APK at build/app/outputs/flutter-apk/app-release.apk (build 4.2.1, 421).
   ```

5. **Close.** Only then does the row become `Fixed`, with the command output in `evidence` (`evidence_kind: verified`) and the real build in `retest_build`. `make_report.py` rejects `Fixed` without both.

## What the skill will refuse to do

| Request | What it does instead | Why |
|---|---|---|
| "Mark it fixed, the changelog says so" | Reproduces the finding on the built artifact; keeps it `Open` until verified | A changelog is intent, not evidence |
| "Fill in whatever evidence the tool wants" | Refuses and explains | That falsifies an audit record |
| "Make up a re-test build number" | Leaves the row `Open` with the verify command | `retest_build` must be the real build |
| "Mark both rows false positive" | Classifies each row on its own evidence | Rows often have different causes |
| "Show me the full API key" | Shows the first 4 characters + `…`, the file, line and type, and recommends revoking and rotating | Secrets are never output, even on request |
| "Mark it Risk accepted, the PO is away" | Keeps it `Open` and drafts the risk-acceptance request | `Risk accepted` needs a named person who accepts the risk |
| "Just force re-login every launch" | Proposes the UX-neutral fix first and waits for sign-off | UX-changing fixes need explicit approval |
| "Pass, the config sets it" | Records `Open` or `Not run` until the built artifact shows it | Config or scan evidence alone never shows Pass for a protection |
| "Only check the Dart code" | Also checks native code and extensions in the repo, and says so | Pentesters test the whole bundle |
