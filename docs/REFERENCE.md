# Reference

Script interfaces, output formats, the `findings.json` format and the data files. For worked examples, see [USAGE.md](USAGE.md). [skills/masvs/SKILL.md](../skills/masvs/SKILL.md) is the authoritative source for the evidence rules; this page summarises them.

- [Repository layout](#repository-layout)
- [Scripts](#scripts)
- [Exit codes and errors](#exit-codes-and-errors)
- [findings.json](#findingsjson)
- [Evidence, status and severity](#evidence-status-and-severity)
- [Scanner behaviour](#scanner-behaviour)
- [Data files](#data-files)
- [Playbooks](#playbooks)
- [Environment variables](#environment-variables)

## Repository layout

```text
masvs-skill/
├── .claude-plugin/
│   ├── marketplace.json        # marketplace "masvs-skill", plugin "masvs"
│   └── plugin.json             # plugin manifest and version
├── skills/masvs/               # the skill: everything Claude loads at runtime
│   ├── SKILL.md                # modes, evidence rules, flows, routing
│   ├── scripts/                # stdlib-only Python 3.9+ scripts, JSON output
│   │   ├── _common.py          # directory walk, secret patterns, redaction
│   │   ├── detect_stack.py
│   │   ├── scan_source.py
│   │   ├── inspect_apk.py
│   │   ├── inspect_ipa.py
│   │   ├── check_pins.py
│   │   └── make_report.py
│   ├── data/
│   │   ├── controls.json       # 24 MASVS v2.1.0 controls
│   │   ├── maswe.json          # 78 MASWE v1.0.0 weaknesses
│   │   ├── rules.json          # 52 scan rules
│   │   └── findings.schema.json
│   └── references/             # per-group playbooks, control and MASWE tables
├── docs/                       # this documentation
│   └── examples/               # synthetic findings.json and its rendered report
├── tests/                      # pytest suite and fixtures
├── evals/                      # pressure scenarios for the skill itself
├── tools/                      # maintainer generators for data/ and references/
└── scripts/package.sh          # builds dist/masvs-<version>.zip
```

In the commands below, `$S` is `skills/masvs/scripts`. Inside an installed plugin or zip, the scripts are in the skill's own `scripts/` folder.

## Scripts

### detect_stack.py

```text
python3 $S/detect_stack.py <root>
```

Walks `<root>` (skipping the folders listed under [Scanner behaviour](#scanner-behaviour)) and reports which stacks are present.

| Key | Type | Meaning |
|---|---|---|
| `stacks` | list | Any of `android`, `flutter`, `ios`, `react-native`, sorted |
| `android_manifests` | list | Paths of every `AndroidManifest.xml`, relative to `<root>` |
| `ios_plists` | list | Paths of every `Info.plist` |
| `dependency_files` | list | `pubspec.yaml`, `pubspec.lock`, `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `build.gradle`, `build.gradle.kts`, `Podfile`, `Podfile.lock` |

Detection: a `pubspec.yaml` with a `flutter:` key or `sdk: flutter` means Flutter; a `package.json` with `react-native` in `dependencies` or `devDependencies` means React Native. Either one also adds `android` and `ios` when sibling `android/` or `ios/` folders exist. An `AndroidManifest.xml` or a Gradle file that applies the Android plugin means Android; an `Info.plist` or a file inside an `.xcodeproj` means iOS.

### scan_source.py

```text
python3 $S/scan_source.py <root> [--stacks flutter,android,ios,react-native] [--include-deps]
```

| Option | Meaning |
|---|---|
| `--stacks` | Comma-separated stacks to scan for, replacing detection. Unknown names are an error. |
| `--include-deps` | Also walk `node_modules`, `Pods`, `vendor` and `.pub-cache`, and report each match's owning package in `owner`. |

| Key | Type | Meaning |
|---|---|---|
| `stacks` | list | Stacks the rules ran for |
| `matches[]` | list | One entry per rule, file and line |
| `matches[].rule` | string | Rule ID from `data/rules.json` |
| `matches[].control` | string | The rule's MASVS control |
| `matches[].maswe` | list | The rule's default MASWE IDs (may be empty) |
| `matches[].file` | string | Path relative to `<root>` |
| `matches[].line` | integer | 1-based line |
| `matches[].snippet` | string | The matched line, trimmed to 200 characters, with secrets redacted |
| `matches[].owner` | string | `app`, or the owning package for files under `node_modules`, `.pub-cache`, `Pods` or a Gradle cache |
| `matches[].status` | string | `match`, or `unresolved` when the matched line holds a placeholder such as `${allowBackup}` |
| `skipped_rules[]` | list | `{rule, reason}` for rules that couldn't run, e.g. `pubspec.lock not found` |

Matches are sorted by file, line and rule. They are **matches, not findings**: severity and status are assigned after reading the playbook.

### inspect_apk.py

```text
python3 $S/inspect_apk.py <apk>
```

Reads the compiled manifest with `aapt2 dump xmltree` and `aapt2 dump badging`, or `apkanalyzer manifest print` when `aapt2` isn't found. Tools are looked up on `PATH`, then under `ANDROID_HOME`, `ANDROID_SDK_ROOT`, `~/Library/Android/sdk` and `~/Android/Sdk` (newest `build-tools/*/aapt2`, or `cmdline-tools/*/bin/apkanalyzer`).

| Key | Type | Meaning |
|---|---|---|
| `min_sdk`, `target_sdk` | integer or null | From `uses-sdk`, falling back to badging |
| `allow_backup` | boolean or null | `android:allowBackup`; `null` when not set |
| `uses_cleartext` | boolean or null | `android:usesCleartextTraffic`; `null` when not set |
| `network_security_config` | string or null | The `android:networkSecurityConfig` resource reference |
| `exported[]` | list | Exported activities, aliases, services, receivers and providers: `{name, permission}`. A component with an intent filter and no `exported` attribute counts as exported when `targetSdk < 31`; when `targetSdk` is unknown it is listed with `"exported": "unknown"`. |
| `permissions` | list | `uses-permission` names |
| `debuggable` | boolean or null | `false` when the attribute is absent; `null` when its value can't be resolved |
| `notes` | list | Explanations for `null` values |

### inspect_ipa.py

```text
python3 $S/inspect_ipa.py <ipa>
```

macOS only. Unzips the IPA to a temporary folder and inspects `Payload/*.app` with `plutil` and `otool`.

| Key | Type | Meaning |
|---|---|---|
| `bundle_id` | string or null | Main app `CFBundleIdentifier` |
| `ats` | object or null | Main app `NSAppTransportSecurity` (`{}` when absent; `null` when Info.plist is unreadable) |
| `bundles[]` | list | `{path, bundle_id, ats}` for the main app and each `PlugIns/*.appex` |
| `binaries[]` | list | The app executable, each `Frameworks/*.framework` executable and each extension executable |
| `binaries[].path` | string | Path inside the `.app` |
| `binaries[].kind` | string | `dart-aot` (Flutter `App.framework`), `objc-swift` or `c` |
| `binaries[].pie` | boolean or null | Position-independent executable (dylibs and bundles count as PIE) |
| `binaries[].arc` | boolean or null | Objective-C ARC; `null` for pure Swift and Dart AOT |
| `binaries[].stack_canary` | boolean or null | `___stack_chk_guard`/`___stack_chk_fail` imported; `null` where not applicable |
| `binaries[].note` | string or null | Why a value is `null` |
| `notes` | list | Bundles whose Info.plist was unreadable |

### check_pins.py

```text
python3 $S/check_pins.py --nsc <xml> [--host H [--port 443] | --chain PEM] [--today YYYY-MM-DD]
```

| Option | Meaning |
|---|---|
| `--nsc` | Android network security config XML (required) |
| `--host`, `--port` | Fetch the live chain with `openssl s_client` and compare its SPKI hashes with the pins. Connects to the host. |
| `--chain` | Compare with a PEM chain file (leaf first) instead of a live host. Takes precedence over `--host`. |
| `--today` | Date used for `days_left` (default: today) |

| Key | Type | Meaning |
|---|---|---|
| `domains[]` | list | One entry per `<domain>` in each `<domain-config>`, including nested ones (a nested config without its own `pin-set` inherits its parent's) |
| `domain` | string | The domain text |
| `include_subdomains` | boolean | `includeSubdomains` attribute |
| `pins` | list | SHA-256 pin values |
| `expiration` | string or null | `pin-set` `expiration` |
| `days_left` | integer or null | Days from `--today` to `expiration`; negative means expired, and Android stops enforcing the pins |
| `backup_pin` | boolean | Two or more pins |
| `pinned_level` | string | `none` (no pins), `unknown` (not compared, or no match), or the highest-priority matched level: `leaf`, `intermediate`, `root` |
| `matched_levels` | list | Every chain level that matched a pin |
| `live_match` | boolean or null | `null` when not compared; `true`/`false` after `--host` or `--chain` |

How domains are compared:

- `--host` compares only the domain entry whose text **exactly equals** the host. Other entries, including a parent domain with `includeSubdomains="true"`, keep `live_match: null`. To check a subdomain, pass the domain exactly as written in the config, or save that host's chain and use `--chain`.
- `--chain` compares the chain with **every** pinned domain in the config.

The certificate at index 0 is the leaf; the last certificate, or any self-signed one, is the root; the rest are intermediates.

### make_report.py

```text
python3 $S/make_report.py <findings.json> --out <dir>
```

Validates `findings.json`, then writes `<dir>/report.md` and `<dir>/report.xlsx` (or `<dir>/report.csv` when `openpyxl` isn't installed). `<dir>` is created if needed.

| Key | Type | Meaning |
|---|---|---|
| `written` | list | Paths of the two files written |
| `warnings` | list | Present only when a MASWE ID isn't mapped to its finding's control |
| `error`, `details` | string, list | On failure: `cannot read findings` or `invalid findings`, with one line per problem |

The report has a summary table (severity × status counts) and a findings table with 13 columns: Finding, Affected Asset, Observation, Impact, Severity, Recommendation, Status, Remediation / Response, Evidence, Re-test Build, Ticket, MASVS Control, MASWE. Evidence is prefixed with `[<evidence_kind>]` when present, and each MASWE ID is followed by its title. In the spreadsheet and CSV, cells starting with `=`, `+`, `-`, `@`, tab or carriage return are prefixed with `'` so they aren't run as formulas.

## Exit codes and errors

| Exit code | Meaning |
|---|---|
| `0` | Success, **or** `{"skipped": "<reason>"}` when a required tool is missing. Record a skipped check as `Not run` with the reason. |
| `2` | Error. The JSON on stdout has an `error` key (and `details` for `make_report.py`). |

Exceptions to "JSON on stdout":

- `make_report.py` argument errors (missing `--out`, missing file argument) come from `argparse` as plain text on stderr, with exit code 2.
- `check_pins.py` argument errors print the `argparse` usage on stderr and a JSON `error` on stdout, with exit code 2.
- `-h`/`--help` prints plain-text usage and exits 0.

Skip messages:

| Script | `skipped` message |
|---|---|
| `inspect_apk.py` | `neither aapt2 nor apkanalyzer found (install Android SDK build-tools or set ANDROID_HOME)` |
| `inspect_ipa.py` | `otool, plutil and unzip are required (macOS with Xcode command line tools)` |
| `check_pins.py` | `openssl not found (install OpenSSL to compute SPKI hashes)` (only with `--host` or `--chain`) |

## findings.json

Schema: [skills/masvs/data/findings.schema.json](../skills/masvs/data/findings.schema.json). Example: [examples/findings.example.json](examples/findings.example.json).

Top level:

| Field | Required | Type | Meaning |
|---|---|---|---|
| `project` | yes | string | App name (not the folder name) |
| `assets` | yes | list of strings | What was assessed: builds, repos, endpoints |
| `generated` | no | string | Report date; defaults to today |
| `findings` | yes | list | One row per finding, plus one row per remaining MASVS control |

Each finding:

| Field | Required | Type | Meaning |
|---|---|---|---|
| `title` | yes | string | Short finding name |
| `control` | yes | string | One MASVS control ID from `data/controls.json`, e.g. `MASVS-STORAGE-2` |
| `maswe` | no | string or list | MASWE IDs from `data/maswe.json` |
| `asset` | yes | string | The affected target, e.g. "iOS Share Extension (ios/ShareExtension)" |
| `observation` | yes | string | What was found, or what was done and what is still needed |
| `impact` | no | string | Consequence if exploited |
| `severity` | yes | enum | `Critical`, `High`, `Medium`, `Low`, `Info` |
| `recommendation` | no | string | How to fix it |
| `status` | yes | enum | `Open`, `Fixed`, `Already mitigated`, `False positive`, `Risk accepted`, `Not run` |
| `response` | no | string | Reply to the auditor |
| `evidence` | no* | string | The command and its output, or the files and lines |
| `evidence_kind` | yes | enum | `verified`, `inferred`, `manual` |
| `retest_build` | no* | string | The build the fix was verified on |
| `ticket` | no | string | Your ticket ID or the auditor's finding ID |

\* Required for some statuses; see below.

Validation rules `make_report.py` enforces, in order:

1. The document matches the schema (types, enums, required fields). If it doesn't, those errors are reported and the checks below don't run.
2. `control` is a control ID in `data/controls.json`.
3. Every `maswe` ID is in `data/maswe.json`.
4. `Fixed` and `Already mitigated` need non-empty `evidence` with `evidence_kind: verified`.
5. `Fixed` needs a non-empty `retest_build`.
6. `False positive` needs non-empty `evidence` with `evidence_kind` `verified` or `inferred` (not `manual`).

Then, as a **warning** (the report is still written): each `maswe` ID should list the finding's `control` in its `controls` in `data/maswe.json`.

## Evidence, status and severity

Copied from [SKILL.md](../skills/masvs/SKILL.md); if the two ever differ, SKILL.md wins.

### Evidence kinds

| `evidence_kind` | Meaning | Examples |
|---|---|---|
| `verified` | A script or command run on a built artifact or a live endpoint showed it | `inspect_apk.py`, `inspect_ipa.py`, an `aapt2` merged manifest, `check_pins.py --host` |
| `inferred` | Source, config or a scan showed it | the source manifest, `build.gradle`, Dart code, `scan_source.py`, `check_pins.py --nsc` alone |
| `manual` | Nothing has exercised it yet | server-side auth, IDOR, hooking, runtime behaviour |

### Pass/fail mapping

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

A protection being present (`Fixed`, `Already mitigated`) never shows Pass on config or scan evidence alone: such a row stays `Open` or `Not run`. `False positive` is exempt, because it claims the finding doesn't apply rather than that a protection works, and it always shows its evidence kind.

### Severity

- **Critical**: remotely exploitable compromise of accounts or data.
- **High**: credentials, tokens or traffic exposed.
- **Medium**: needs device access or a specific condition.
- **Low**: defence in depth.
- **Info**: Not run rows and notes.
- **Leaked credentials and keystores** (committed signing keys, service-account keys, API secrets): High by default; Critical once a release signing key or a production cloud credential is confirmed. Rate by exposure, not by whether the file ships in the build.

## Scanner behaviour

- **Skipped folders.** `build`, `.dart_tool`, `.gradle`, `DerivedData`, `.git` are always skipped. `node_modules`, `Pods`, `vendor` and `.pub-cache` are skipped unless `--include-deps` is given. `detect_stack.py` skips all of them.
- **Skipped files.** Files over 2 MB, non-regular files, and binary files (a NUL byte in the first 8 KB) are not read.
- **Rule selection.** A rule runs when one of its `stacks` was detected (or given with `--stacks`), or its stacks are `"*"`, and the file's repo-relative path matches its `files` glob and not its `exclude_files` glob.
- **Filename rules.** Rules with `exists: true` (SECRET-KEYSTORE-1, SECRET-KEYSTORE-2, SECRET-KEYPROPS-1) match on the path alone at line 1, never read the file, and skip paths that `git check-ignore` reports as ignored.
- **Lockfile-aware rules.** A rule with `requires` (FLT-STORAGE-2) reports only when the nearest `pubspec.lock` (searching up to `<root>`) pins the package at or below `max_major`. If no lockfile is found, the rule is listed in `skipped_rules` instead.
- **Absent rules.** A rule with `absent: true` (AND-BACKUP-2, AND-NET-2, IOS-HARDEN-1) fires once per file when its pattern is **not** found, e.g. an `<application>` that doesn't set `android:allowBackup`.
- **Placeholders.** A match whose line hits the rule's `unresolved_pattern` (such as `${allowBackup}`, or `flutter.minSdkVersion` for AND-SDK-1) gets `status: unresolved`.
- **Deduplication.** One match per rule, file and line.
- **Redaction.** Snippets have known token formats (AWS, GitLab, GitHub, Google API, Slack, private keys, Stripe live keys, `sk-` API keys, JWTs) cut to their first 4 characters plus `…`, and quoted literals of 16+ characters that mix letters and digits cut the same way. `make_report.py` applies the same redaction to every cell, `inspect_apk.py` and `inspect_ipa.py` to their whole output, and `check_pins.py` to domain names and error messages.

## Data files

| File | Contents | Maintained by |
|---|---|---|
| [data/controls.json](../skills/masvs/data/controls.json) | 24 MASVS v2.1.0 controls: `id`, `group`, `summary` (paraphrased), `maswe`, `mastg_tests` (candidates via shared MASWE IDs), `url` | `tools/map_mastg_tests.py` for `mastg_tests` |
| [data/maswe.json](../skills/masvs/data/maswe.json) | 78 MASWE v1.0.0 weaknesses: `id`, `title`, `requirement`, `group`, `controls`, `platforms`, `cwe`, `modes`, `mitigations`, `url` | Generated by `tools/gen_maswe.py` from an OWASP/maswe release tag |
| [data/rules.json](../skills/masvs/data/rules.json) | 52 scan rules; the `fields` block at the top documents every key | By hand; see [CONTRIBUTING.md](../CONTRIBUTING.md#add-a-rule) |
| [data/findings.schema.json](../skills/masvs/data/findings.schema.json) | JSON Schema for `findings.json` | By hand |

## Playbooks

Claude reads only the playbooks for the groups an audit hits.

| Topic | Playbook | Controls |
|---|---|---|
| Local storage, backups, logs, keychain/keystore, secure-storage plugins | [storage.md](../skills/masvs/references/storage.md) | STORAGE-1/2 |
| Algorithms, keys, random, hard-coded keys | [crypto.md](../skills/masvs/references/crypto.md) | CRYPTO-1/2 |
| Sessions, tokens, biometrics, step-up, logout | [auth.md](../skills/masvs/references/auth.md) | AUTH-1/2/3 |
| TLS, cleartext, ATS, network security config, pinning | [network.md](../skills/masvs/references/network.md) | NETWORK-1/2 |
| IPC, exported components, deep links, WebViews, screenshots | [platform.md](../skills/masvs/references/platform.md) | PLATFORM-1/2/3 |
| minSdk, forced update, vulnerable deps, input validation | [code.md](../skills/masvs/references/code.md) | CODE-1..4 |
| Root/jailbreak detection, tamper, obfuscation, anti-debug | [resilience.md](../skills/masvs/references/resilience.md) | RESILIENCE-1..4 |
| Data minimisation, consent, telemetry, tracking | [privacy.md](../skills/masvs/references/privacy.md) | PRIVACY-1..4 |
| Known false positives with an evidence recipe | [false-positives.md](../skills/masvs/references/false-positives.md) | — |
| Control list with MASWE and MASTG IDs | [controls.md](../skills/masvs/references/controls.md) | — |
| Weakness catalog as tables by group | [maswe.md](../skills/masvs/references/maswe.md) | — |

## Environment variables

| Variable | Used by | Effect |
|---|---|---|
| `ANDROID_HOME` | `inspect_apk.py` | Android SDK root searched for `build-tools/*/aapt2` and `cmdline-tools/*/bin/apkanalyzer` |
| `ANDROID_SDK_ROOT` | `inspect_apk.py` | Same, checked after `ANDROID_HOME` |
| `MASVS_DENYLIST` | `tests/test_references.py` | Comma-separated words that must not appear anywhere in `skills/masvs/` (client names, hosts, bundle IDs). Without it the test is skipped. |
