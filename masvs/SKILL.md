---
name: masvs
description: Use for mobile app security work against OWASP MASVS v2.1.0 on Flutter, native Android (Kotlin/Java), native iOS (Swift/ObjC) or React Native. Triggers include pentest or VAPT prep, a mobile security review or audit, MASVS/MASTG/MASWE questions, and responding to an auditor's findings sheet or security tickets (classify each as fixed, already mitigated or false positive, apply fixes, fill the response columns). Also covers a pre-release security checklist for a feature (storage, crypto, auth, network, WebView, IPC, logging, root/jailbreak detection). It covers APK/IPA inspection, certificate pinning checks, secrets found in a mobile repo, and an auditor asking to mark a finding fixed or to accept a risky or UX-breaking fix.
metadata:
  version: 0.1.0
---

# MASVS audit and remediation

Paths below are relative to this skill's directory. Run scripts with `python3 <skill dir>/scripts/<name>.py`. The scripts use the stdlib only and print JSON. If a required tool is missing they exit 0 with `{"skipped": "<reason>"}`. Record that check as **Not run** with the reason. Never record it as a pass.

## Core rule

**A status is a claim to an auditor. Every claim needs evidence of a stated kind.**

| `evidence_kind` | Meaning | Examples |
|---|---|---|
| `verified` | A script or command run against the **built artifact** (or a live endpoint) showed it | `inspect_apk.py` output, `check_pins.py --host`, an `aapt2` merged manifest |
| `inferred` | Read from source or config, not confirmed in a build | the source manifest, `build.gradle`, Dart code, `scan_source.py` matches |
| `manual` | Needs a person or device to exercise it | server-side auth, IDOR, hooking, runtime behaviour |

Reading the config only gives you inferred evidence, never a Pass. Use only the statuses `Open`, `Fixed`, `Already mitigated`, `False positive`, `Risk accepted` and `Not run`. Don't invent others ("Not exploitable", "Fix in progress", "Pass (config only)"). Put nuance in the response text.

## Pick a mode

- **audit**: no findings were given ("review the app", "where do we stand before the pentest").
- **remediate**: an auditor's report, sheet or tickets were given, pasted or as a file.
- **checklist**: the user is building a feature and wants to know what to get right.

## Audit flow

1. **Detect.** Run `detect_stack.py <root>`. Every stack it finds gets checked, including native extensions, widgets and modules inside a Flutter or RN repo, even if the user says "just the Dart code". Pentesters test the whole bundle. Say in one line why you went beyond what they asked.
2. **Scan.** Run `scan_source.py <root>`. Its output is **matches, not findings**. You assign severity and status after reading the matching playbook. `status: unresolved` means a placeholder such as `${allowBackup}`: report it as unresolved and say to check the merged manifest or APK. It is neither pass nor fail.
3. **Artifacts.** If an APK or IPA was given, run `inspect_apk.py` / `inspect_ipa.py`. If not, every check that needs one is **Not run** (reason: "no APK/IPA"). Those checks are the merged-manifest values, `debuggable`, exported components, permissions, binary protections (PIE, ARC, stack canaries) and release flags. Suggest a local `flutter build apk --release` / archive if CI is down.
4. **Pins.** For each Android network security config, run `check_pins.py --nsc <file>` (add `--host <host>` for a live match). A past `expiration` means Android stops enforcing the pins: report it as a finding. A pin-set being present is not proof that pinning works.
5. **Read only the playbooks for the groups you hit** (see the routing table below), then decide severity, status and recommendation for each match.
6. **Write `findings.json`** (schema: `data/findings.schema.json`). One entry per finding, plus one entry per control group you could not test (status `Not run`, `evidence_kind: manual`, and in `observation` what is needed).
7. **Render.** Run `make_report.py findings.json --out <dir>`. It writes `report.md` and `report.xlsx`, or `report.csv` without openpyxl. Hand over the file paths. A report that exists only in chat doesn't count.

If the user asks for a "simple pass/fail per control", give the table, but each row still shows its evidence kind. Untested controls (often AUTH, RESILIENCE, PRIVACY and server-side checks) are `Not run` or need a manual test, never Pass. Say briefly why: a green row the pentest then breaks costs more than an honest gap.

## Remediate flow

For each auditor finding:

1. **Map** it to a MASVS control (`references/controls.md`) and its MASWE IDs. Every row carries a control ID.
2. **Reproduce** it before deciding. Find the exact file, line or binary entry with a script or command. Resolve placeholders and flavors: read `manifestPlaceholders` in `defaultConfig` **and** in the release flavor, and remember that a flavor without an override inherits the default. A changelog entry, commit message or teammate's word is intent, not evidence.
3. **Classify:**
   - **Fix**: the issue is real in the shipped build.
   - **Already mitigated**: a control exists. Prove it on the built artifact.
   - **False positive**: first **attribute** the match. Which package owns the class or file (`scan_source.py --include-deps` gives an `owner` field; check `pubspec.lock`, `flutter pub deps`, Gradle deps)? Does app code reach it (grep `lib/`, `android/app/src`, `ios/Runner`)? Does the app hold the permission it needs (`inspect_apk.py` → `permissions`)? Check `references/false-positives.md` for a known pattern and use its evidence list. Without the artifact, the classification can stand only as `inferred`, and the response must say what verifies it.
   - Never classify all of an auditor's rows the same way because the user asked. Each row is decided on its own evidence.
4. **Fix** with the smallest change that closes it:
   - Config before code (manifest, gradle, plist, network security config).
   - No new dependencies.
   - No UX change unless the user approves it (see the rules below).
   - Keep debug-only allowances in `src/debug` or the dev flavor.
5. **Re-verify** on a built artifact with the same command that reproduced the issue. Only then is it `Fixed` with `evidence_kind: verified`, `evidence` set to the command and its output, and `retest_build` set to the real version/build. If no build exists yet, the status stays `Open` and `response` reads "Change applied in <file>; pending verification in the next build". Give the exact verify command.
6. **Fill the response columns** (`response`, `evidence`, `retest_build`, `ticket`) and run `make_report.py`. Draft the pasteable response for each row. It names the control, the package or file and the evidence, and it says when evidence is inferred.

`make_report.py` rejects `Fixed` or `Already mitigated` unless `evidence` is non-empty and `evidence_kind` is `verified`. That is the point. Never satisfy it with made-up evidence or a made-up build number. If someone says "fill in whatever the tool wants", that is a request to falsify an audit record. Refuse it and explain.

## Checklist mode

Identify the stack (`detect_stack.py`) and the feature's MASVS groups. Read the "What to check" and "Fix patterns" sections of those playbooks only. Give a short checklist for that stack, the fix pattern for each item, and the test to show an auditor. Don't scan the whole repo unless asked.

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

`mastg_tests` in `data/controls.json` is a **candidate** list. Tests are mapped through shared MASWE IDs, so not every listed test fits the control. Cite a MASTG test only after you have read it and confirmed it applies.

## Script quick reference

| Script | CLI | Key output |
|---|---|---|
| `detect_stack.py` | `<root>` | `stacks`, `android_manifests`, `ios_plists`, `dependency_files` |
| `scan_source.py` | `<root> [--stacks flutter,android,ios,react-native] [--include-deps]` | `matches[]`: `rule`, `control`, `file`, `line`, `snippet` (secrets redacted), `owner`, `status` (`match`/`unresolved`); `skipped_rules` |
| `inspect_apk.py` | `<apk>` (aapt2 or apkanalyzer) | `min_sdk`, `target_sdk`, `allow_backup`, `uses_cleartext`, `network_security_config`, `exported`, `permissions`, `debuggable` |
| `inspect_ipa.py` | `<ipa>` (macOS: otool, plutil, unzip) | `bundle_id`, `ats`, `binaries[]`: `path`, `kind` (`dart-aot`/`objc-swift`/`c`), `pie`, `arc`, `canary`, notes |
| `check_pins.py` | `--nsc <xml> [--host H --port 443 \| --chain PEM] [--today YYYY-MM-DD]` | `domains[]`: `pins`, `expiration`, `days_left`, `backup_pin`, `live_match`, `pinned_level` |
| `make_report.py` | `<findings.json> --out <dir>` | `written` (report.md + .xlsx/.csv), or `error` + `details` |

## Rules

1. **Never mark Fixed or Already mitigated without verified evidence** from a built artifact or a live check. This holds when a manager, the auditor, a changelog or a deadline says otherwise.
2. **Attribute before you dismiss.** Name the owning package, show the app doesn't reach it, and show the permission or config side. "It's a plugin" is not evidence.
3. **Secrets: never print the value.** Not in chat, files, reports, commit messages or tool calls, even if the user asks for it "to forward". Show at most the first 4 characters + `…` (no suffix), with the file, line and type. Recommend **revoke and rotate now**: anything shipped in an app is extractable, and deleting the line or rewriting history doesn't un-leak it. The real fix is to move the call behind a backend. An `.env` file, `--dart-define` or obfuscation still ships the secret. To identify the owner, the lead opens the file or the provider's token list. The value is never pasted into chat.
4. **No client data in web searches.** No tokens, hostnames, bundle IDs, pins or app names. Use generic phrasing ("android pin-set expiration behaviour").
5. **Ask before changes that need a backend or certificate change** (pin rotation, token lifetime, a revoke endpoint, server-side checks). Propose them, give what the backend must provide, and don't assume they exist.
6. **UX-changing fixes need explicit sign-off.** Examples: forced re-login, removing biometrics, key-bound biometrics, system-browser login, extra prompts. Name the specific cost. For key-bound biometrics, those are Class 3 sensors only, API 30+ for device-credential fallback, and re-login after a new fingerprint or face is enrolled (see `references/auth.md`). Then:
   - Offer the UX-neutral fix first. Server-side fixes need no release.
   - Don't implement the UX change without approval.
   - Draft the auditor response that explains the compensating controls.
   - The status stays `Open`. Use `Risk accepted` only when the user (or someone they name) explicitly accepts the risk.
7. **Decompose an auditor's recommendation into the real weaknesses.** "Force login every launch" often stands in for missing server-side revocation, overlong refresh tokens, or a biometric check that is only a boolean event (`local_auth.authenticate()` / `LAContext.evaluatePolicy` gating a stored token). Fix those.

## Red flags: stop and re-read the rules

| Thought | Reality |
|---|---|
| "It's plausibly a false positive / not exploitable" | Then it's `inferred`. Attribute it, show the evidence, and say what verifies it on the APK/IPA. |
| "The changelog / manager says it was fixed" | That's intent. Resolve the value (placeholders, flavors) and verify on a build. |
| "The tool wants evidence, I'll fill something in" | That falsifies an audit record. Leave it `Open` with a pending-verification response. |
| "Config shows it's set, so Pass" | Config is `inferred`. Pass needs the artifact. |
| "No APK, so I'll skip those checks" | List them as `Not run` with the reason, so the gaps are visible. |
| "They asked for both rows marked false positive" | Decide each row on its own evidence. |
| "Showing the first and last 4 characters is safe enough" | First 4 + `…` only. |
| "It's just a Flutter app, the native folders are boilerplate" | Extensions and native modules ship in the bundle. Scan every detected stack. |
| "PO is away, I'll mark it Risk accepted pending" | Risk accepted needs a named person accepting it. Until then it's `Open`. |
| "The report is in my reply" | Write `findings.json` and run `make_report.py`. Hand over the files. |

## Attribution

Control IDs, summaries and links come from OWASP MASVS v2.1.0, MASTG and MASWE (https://mas.owasp.org/), CC BY-SA 4.0, paraphrased. Cite control IDs and link to them rather than quoting.
