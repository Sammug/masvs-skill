---
name: masvs
description: Use for mobile app security work on Flutter, native Android (Kotlin/Java), native iOS (Swift/ObjC) or React Native apps measured against OWASP MASVS. Triggers include pentest or VAPT prep, a mobile security review or audit, questions about MASVS, MASTG or MASWE, an auditor's findings sheet or security tickets to respond to, a request to mark a finding fixed or false positive, a pre-release security checklist for a feature (storage, crypto, auth, network, WebView, IPC, logging, root/jailbreak detection), APK/IPA inspection, certificate pinning, and secrets found in a mobile repo.
metadata:
  version: 0.3.0
---

# MASVS audit and remediation

Paths below are relative to this skill's directory. Run scripts with `python3 <skill dir>/scripts/<name>.py`. The scripts use only the Python 3.9+ stdlib and print JSON. If a required tool is missing, they exit 0 with `{"skipped": "<reason>"}`; record that check as `Not run` with the reason.

## Core rule: evidence and status

**A status is a claim to an auditor, and every claim needs evidence of a stated kind.**

The three evidence kinds are defined here once and apply to every status:

| `evidence_kind` | Meaning | Examples |
|---|---|---|
| `verified` | A script or command run on a built artifact or a live endpoint showed it | `inspect_apk.py`, `inspect_ipa.py`, an `aapt2` merged manifest, `check_pins.py --host` |
| `inferred` | Source, config or a scan showed it | the source manifest, `build.gradle`, Dart code, `scan_source.py`, `check_pins.py --nsc` alone |
| `manual` | Nothing has exercised it yet | server-side auth, IDOR, hooking, runtime behaviour |

Every row carries the kind that matches how it was established. That includes `Open` (e.g. an `inspect_apk.py` output showing `allow_backup: true` is `verified`) and `Not run` (`verified` when some checks ran on the artifact, otherwise `inferred` or `manual`).

Use only these statuses: `Open`, `Fixed`, `Already mitigated`, `False positive`, `Risk accepted`, `Not run`. Don't invent others such as "Not exploitable" or "Fix in progress"; put nuance in the response text. `evidence_kind` is required on every finding. `make_report.py` rejects `Fixed` and `Already mitigated` unless `evidence` is non-empty and `evidence_kind` is `verified`, `Fixed` without a `retest_build`, and `False positive` without evidence of kind `verified` or `inferred`. Never satisfy it with made-up evidence or a made-up build number. "Fill in whatever the tool wants" is a request to falsify an audit record: refuse and explain.

**Pass/fail mapping.** This is the only place the mapping is defined. Use it in any pass/fail view, and keep the chat summary and the report consistent with it. Every cell ends with the row's evidence kind in brackets, for example `Fail [inferred]`, `Not tested [manual]` or `Pass (verified: inspect_apk allow_backup=false) [verified]`.

| Status [`evidence_kind`] | Shown as `<label> [<kind>]` |
|---|---|
| `Already mitigated` [verified]: every automated check for the control ran on the artifact or a live endpoint and passed | Pass (verified: <check>) [verified] |
| `Already mitigated` [verified], when the control also has manual parts (AUTH, RESILIENCE, server-side) | Pass (automated checks); manual test pending [verified] |
| `Fixed` [verified] | Pass (fixed, verified) [verified] |
| `False positive` [verified or inferred] | Pass (false positive) [<kind>] |
| `Open` [any kind] | Fail [<kind>] |
| `Risk accepted` [any kind] | Fail (risk accepted) [<kind>] |
| `Not run` [verified, partial]: only some automated checks ran on the artifact; `evidence` lists which ran and passed, and which didn't run and why | Not tested (partly verified: <checks>) [verified] |
| `Not run` [manual or inferred] | Not tested [<kind>] |

A protection being present (`Fixed`, `Already mitigated`) never shows Pass on config or scan evidence alone: such a row stays `Open` or `Not run`. `False positive` is exempt, because it claims the finding doesn't apply rather than that a protection works, and it always shows its evidence kind. A green row that the pentest then breaks costs more than an honest gap, so tell the user that in one line if they push for a clean sheet.

**Severity** (you assign it; the scanner doesn't):
- Critical: remotely exploitable compromise of accounts or data.
- High: credentials, tokens or traffic exposed.
- Medium: needs device access or a specific condition.
- Low: defence in depth.
- Info: Not run rows and notes.
- Leaked credentials and keystores (committed signing keys, service-account keys, API secrets): High by default; Critical once a release signing key or a production cloud credential is confirmed. Rate by exposure, not by whether the file ships in the build. Recommend revoking or rotating, because deleting the file doesn't un-leak it.

**MASWE (weaknesses).** MASVS says what to achieve; MASWE names the specific weakness that breaks it. `data/maswe.json` is the full OWASP MASWE catalog (version in its `version` field): for each ID, its `title`, `requirement`, `controls`, `platforms`, `cwe`, `modes` (how the weakness gets introduced) and `mitigations`. `references/maswe.md` is the same catalog as tables grouped by MASVS group. Fill `maswe` on every finding:
- A scan match carries its rule's `maswe`. Keep it if it describes what you confirmed, otherwise replace it.
- Otherwise pick from the control's `maswe` list in `data/controls.json`, matching what you found against each candidate's `modes`. Use the weakness, not the nearest title: a token logged by a plugin is MASWE-0005 whether or not the auditor wrote "logging".
- Leave it empty when no weakness fits. Never invent an ID: `make_report.py` rejects any ID not in the catalog, and warns (`warnings`) when an ID isn't mapped to the finding's `control`. Resolve the warning by fixing the control or the ID, not by ignoring it.
- In a response or checklist, quote the weakness's `requirement` as the acceptance criterion and name its mitigation, then link its `url`.

## Pick a mode

- **audit**: no findings given ("review the app", "where do we stand before the pentest").
- **remediate**: an auditor's report, sheet or tickets are given, pasted or as a file.
- **checklist**: the user is building a feature and wants to get it right.

## Audit flow

1. **Detect.** Run `detect_stack.py <root>`. Check every stack it finds, including native extensions, widgets and modules inside a Flutter or React Native repo, even if the user says "just the Dart code". Pentesters test the whole bundle; say so in one line. Name the target in `asset` (e.g. "iOS Share Extension (ios/ShareExtension)") and rate it like the main app. Platforms in the repo that are out of scope (macOS, web) get one `Not run` row listed as "not assessed", not a finding per scan match; drop their scan matches (e.g. a macOS Podfile) from the findings.
2. **Scan.** Run `scan_source.py <root>`. Its output is **matches, not findings**: you assign severity and status after reading the playbook. Rules with a filename trigger (SECRET-KEYSTORE-*, SECRET-KEYPROPS-1) match on the path alone, never read the file and skip git-ignored paths; SECRET-SA-1 matches a service-account key file by its `"type"` field. Controls for committed secrets: CRYPTO-2 for signing keys, keystores and service-account private keys (as SECRET-PEM-1), STORAGE-2 for tokens and API keys found in the repo (SECRET-GOOGLE-1 and similar). When the value also ships inside the app package (in `lib/`, assets or the built APK/IPA), it is MASWE-0004: record it under STORAGE-1. Confirm with `git ls-files` and `git log --stat -- <path>` whether the file is tracked or only in history, and whether it is a debug or release key. `status: unresolved` means a placeholder such as `${allowBackup}`. Resolve it from `manifestPlaceholders` (`defaultConfig` plus the release flavor; a flavor without an override inherits the default) and report the value as `inferred`. If it can't be resolved, record it as `Not run` with `evidence_kind: inferred`: "unresolved placeholder: check merged manifest/APK".
3. **Artifacts.** If an APK or IPA is given, run `inspect_apk.py` / `inspect_ipa.py`. Otherwise every check that needs a build is `Not run` ("no APK/IPA"): merged-manifest values, `debuggable`, exported components, permissions, binary protections and release flags. If CI is down, suggest a local `flutter build apk --release` or an archive.
4. **Pins.** Run `check_pins.py --nsc <file>` for each network security config, adding `--host <host>` for a live match. A past `expiration` means Android stops enforcing the pins, so report it as a finding. A pin-set being present doesn't prove pinning works.
5. **Read only the playbooks for the groups you hit** (see Routing), then decide each match.
6. **Write `findings.json`** (schema: `data/findings.schema.json`) to `<app>/.masvs/`, or to a path the user names.
   - Set `project` to the app name, not the folder name.
   - Add one row per finding. Several findings may share a control.
   - Add one row for every other MASVS control. If every automated check for it was verified clean on an artifact, record it as `Already mitigated` (verified, with the checks named). If only some ran, record `Not run` with `evidence_kind: verified`, and list the checks that ran and passed and those that didn't (and why). If none ran, record it as `Not run` with `evidence_kind: manual` and the reason (e.g. "no APK/IPA"), severity `Info`, with `observation` saying what was done and what is still needed, and `asset` naming what the check needs (e.g. "Android release APK (not provided)").
   - `control` must be a single ID from `data/controls.json`; `make_report.py` rejects anything else.
7. **Render.** Run `make_report.py findings.json --out <dir>` (default `<app>/.masvs/`, or the path the user names), hand over the file paths, and tell the user to gitignore `.masvs/` because the report holds security findings. A report that exists only in chat doesn't count.

## Remediate flow

For each auditor finding:

1. **Map** it to a MASVS control (`references/controls.md`) and the MASWE weakness it describes (`references/maswe.md`; match the auditor's observation against `modes` in `data/maswe.json`). An auditor's finding often names a symptom or a tool's check rather than the weakness; map the weakness, and say in the response which one it is.
2. **Reproduce** it before deciding: find the exact file, line or binary entry with a script or command, and resolve placeholders and flavors as in audit step 2. A changelog entry, commit message or teammate's word is intent, not evidence. If no script fits (server-side or auth findings), read the code path (`inferred`) and list the playbook's manual test (`manual`).
3. **Classify each row on its own evidence**, never all rows the same way because the user asked.
   - **Fix**: the issue is real in the shipped build.
   - **Already mitigated**: a control exists; prove it on the built artifact.
   - **False positive**: first attribute the match (rule 2), using `references/false-positives.md` for known patterns. Without the artifact, use `False positive` with `evidence_kind: inferred`: `evidence` lists the attribution commands, and `response` names the artifact check that will confirm it. Don't park a well-attributed false positive as `Open`.
4. **Fix** with the smallest change that closes it: config before code, no new dependencies, and debug-only allowances kept in `src/debug` or the dev flavor. Apply fixes that are config-only or a small code change and need no backend or UX change. Propose the rest and wait (rules 4 and 5).
5. **Re-verify** on a built artifact with the command that reproduced the finding. Only then mark it `Fixed`, with the command and its output in `evidence` and the real build in `retest_build`. Until then it stays `Open`, with the response "Change applied in <file>; pending verification in the next build" and the exact verify command.
6. **Fill the response columns** (`response`, `evidence`, `retest_build`, `ticket`) and run `make_report.py`. If there is no `findings.json`, create one from the auditor's rows, with `ticket` holding the auditor's ID. Each pasteable response names the control, the package or file and the evidence, and says when evidence is inferred.

## Checklist mode

Identify the stack (`detect_stack.py`) and the feature's MASVS groups. Read only the "What to check" and "Fix patterns" sections of those playbooks, and the MASWE entries for those groups in `data/maswe.json`, filtered by `platforms`. For that stack, give a short checklist with one item per relevant weakness (its ID and `requirement`), the fix pattern for each item, and the test to show an auditor. Skip weaknesses the feature can't introduce, and say which you skipped in one line.

## Routing

| Topic | Playbook | Controls |
|---|---|---|
| Local storage, backups, logs, keychain/keystore, secure-storage plugins | `references/storage.md` | STORAGE-1/2 |
| Algorithms, keys, random, hard-coded keys | `references/crypto.md` | CRYPTO-1/2 |
| Sessions, tokens, biometrics, step-up, logout | `references/auth.md` | AUTH-1/2/3 |
| TLS, cleartext, ATS, network security config, pinning | `references/network.md` | NETWORK-1/2 |
| IPC, exported components, deep links, WebViews, screenshots | `references/platform.md` | PLATFORM-1/2/3 |
| minSdk, forced update, vulnerable deps, input validation | `references/code.md` | CODE-1..4 |
| Root/jailbreak detection, tamper, obfuscation, anti-debug | `references/resilience.md` | RESILIENCE-1..4 |
| Data minimisation, consent, telemetry, tracking | `references/privacy.md` | PRIVACY-1..4 |
| Known false positives with an evidence recipe | `references/false-positives.md` | — |
| Control list, MASWE and MASTG IDs, links | `references/controls.md`, `data/controls.json` | — |
| Weakness catalog: titles, requirements, modes, mitigations | `references/maswe.md`, `data/maswe.json` | — |

`mastg_tests` in `data/controls.json` is a **candidate** list mapped through shared MASWE IDs. Cite a MASTG test only after reading it and confirming that it applies.

## Script quick reference

| Script | CLI | Key output |
|---|---|---|
| `detect_stack.py` | `<root>` | `stacks`, `android_manifests`, `ios_plists`, `dependency_files` |
| `scan_source.py` | `<root> [--stacks flutter,android,ios,react-native] [--include-deps]` | `stacks`; `matches[]`: `rule`, `control`, `maswe`, `file`, `line`, `snippet` (secrets redacted), `owner`, `status` (`match`/`unresolved`); `skipped_rules` |
| `inspect_apk.py` | `<apk>` (aapt2 or apkanalyzer; found in the Android SDK build-tools if not on PATH) | `min_sdk`, `target_sdk`, `allow_backup`, `uses_cleartext`, `network_security_config`, `exported`, `permissions`, `debuggable` (`null` + `notes` when unresolved) |
| `inspect_ipa.py` | `<ipa>` (macOS: otool, plutil, unzip) | `bundle_id`, `ats` (main app; `null` + `notes` if its Info.plist is unreadable); `bundles[]`: `path`, `bundle_id`, `ats` (main app and each `PlugIns/*.appex`); `binaries[]` (app, frameworks, extensions): `path`, `kind` (`dart-aot`/`objc-swift`/`c`), `pie`, `arc`, `stack_canary`, `note` |
| `check_pins.py` | `--nsc <xml> [--host H --port 443 \| --chain PEM] [--today YYYY-MM-DD]` | `domains[]`: `pins`, `expiration`, `days_left`, `backup_pin`, `live_match`, `pinned_level` |
| `make_report.py` | `<findings.json> --out <dir>` | `written` (report.md + .xlsx/.csv) and `warnings` (MASWE/control mismatches), or `error` + `details` |

## Rules

1. **Never mark `Fixed` or `Already mitigated` without verified evidence** (Core rule), even when a manager, the auditor, a changelog or a deadline says otherwise.
2. **Attribute before you dismiss.** Name the owning package (the `owner` field from `scan_source.py --include-deps`, `pubspec.lock`, `flutter pub deps` or Gradle deps). If `~/.pub-cache` is missing, use the class's package path plus `pubspec.lock`, and say so in the evidence. Show that app code doesn't reach it (grep `lib/`, `android/app/src`, `ios/Runner`), and show the permission or config side (`inspect_apk.py` → `permissions`). "It's a plugin" is not evidence.
3. **Never output a secret's value**: not in chat, files, reports, commits or tool calls (including web searches), even on request. Show the first 4 characters + `…`, with the file, line and type. Recommend **revoking and rotating it now**, because a value shipped in an app is extractable and deleting it from history doesn't un-leak it. Move the call behind a backend; `.env`, `--dart-define` and obfuscation still ship the value. The owner is found from the file or the provider's token list, and leak use from the provider's audit log.
4. **Ask before backend or certificate changes** (pin rotation, token lifetime, revoke endpoint, server checks). Say what the backend must provide, and don't assume it exists. Keep client data (tokens, hostnames, bundle IDs, pins, app names) out of web searches.
5. **UX-changing fixes need explicit sign-off.** Examples: forced re-login, removing biometrics, key-bound biometrics, system-browser login, extra prompts. Name the specific cost; for key-bound biometrics that is Class 3 sensors only, API 30+ for device-credential fallback, and re-login after a new enrolment (`references/auth.md`). Offer the UX-neutral fix first, don't implement the UX change without approval, and draft an auditor response that explains the compensating controls. The status stays `Open`. Use `Risk accepted` only when a named person explicitly accepts the risk.
6. **Break an auditor's recommendation into the real weaknesses.** "Force login every launch" often stands in for missing server-side revocation, overlong refresh tokens, or a biometric check that is only a boolean event (`local_auth.authenticate()` / `LAContext.evaluatePolicy` gating a stored token). Fix those.

## Red flags: stop and re-read

| Thought | See |
|---|---|
| "Plausibly a false positive / not exploitable" | Rule 2; without the artifact, it's `inferred` |
| "The changelog or manager says it was fixed" | Remediate step 2; rule 1 |
| "The tool wants evidence, I'll fill something in" | Core rule: that falsifies an audit record |
| "The config shows it's set, so Pass" | Pass/fail mapping |
| "No APK, so I'll skip those checks" | Audit step 3: `Not run`, with the reason |
| "They asked for both rows marked false positive" | Remediate step 3 |
| "First and last 4 characters is safe enough" | Rule 3 |
| "The native folders are boilerplate" | Audit step 1 |
| "The PO is away, so I'll mark it Risk accepted pending" | Rule 5 |
| "This MASWE ID looks close enough" | Core rule, MASWE IDs |
| "The report is in my reply" | Audit step 7 |

## Attribution

Control IDs, summaries and links come from OWASP MASVS v2.1.0, MASTG and MASWE (https://mas.owasp.org/), CC BY-SA 4.0. Control summaries are paraphrased; MASWE titles and requirements are quoted. Cite IDs and link to them.
