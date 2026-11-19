# Troubleshooting

Find the symptom, check the cause, apply the fix. Script options and output keys are in [REFERENCE.md](REFERENCE.md).

## Installing and invoking

| Symptom | Cause | What to do |
|---|---|---|
| `/masvs` isn't found | Plugin skills are namespaced by plugin name | Use `/masvs:masvs`. Plain `/masvs` works only with a zip install into `.claude/skills/`. |
| The skill doesn't load when I ask about security | The request didn't mention MASVS, MASWE, a pentest, VAPT, a mobile security audit or auditor findings, or the plugin isn't active | Name it ("Run a MASVS audit…") or call `/masvs:masvs` directly. Check the plugin is listed under `/plugin` → **Installed**. |
| The plugin is installed but not active | An in-session install sometimes needs a reload; a shell install loads at the next start | Run `/reload-plugins`, or start a new Claude Code session. |
| `/plugin` commands fail in `claude -p` | Slash commands don't run in headless mode | Install from a shell: `claude plugin marketplace add Sammug/masvs-skill`, then `claude plugin install masvs@masvs-skill`. |
| A zip install isn't picked up | The folder is nested one level too deep (`.claude/skills/masvs/masvs/SKILL.md`) or in the wrong place | Unzip so the path is `~/.claude/skills/masvs/SKILL.md` or `<app>/.claude/skills/masvs/SKILL.md`. |

## Audit results

| Symptom | Cause | What to do |
|---|---|---|
| Most rows are `Not run` | No APK or IPA was given, so build-only checks (merged manifest, `debuggable`, exported components, permissions, binary protections, release flags) couldn't run | Build a release artifact and include its path in the prompt. See [USAGE.md](USAGE.md#source-plus-apk-and-ipa). |
| Rows I fixed are still `Open` | `Fixed` needs verified evidence from a built artifact and a real `retest_build` | Build, then ask the skill to re-verify those findings on the new APK/IPA. See [the fix loop](USAGE.md#the-fix-build-re-verify-close-loop). |
| A row is `Open` even though the config sets the protection | Config or scan evidence alone never shows Pass for a protection | Provide the built artifact so the check can run on it. |
| The skill asks before changing pins, tokens or login behaviour | Backend and UX-changing fixes need sign-off | Approve the change or pick the UX-neutral option it offers. The row stays `Open` until the fix is verified. |

## Script output

| Symptom | Cause | What to do |
|---|---|---|
| `inspect_apk.py` returns `{"skipped": "neither aapt2 nor apkanalyzer found (install Android SDK build-tools or set ANDROID_HOME)"}` | No `aapt2` on `PATH` or in the SDK locations it searches | Install Android SDK build-tools, or set `ANDROID_HOME` (or `ANDROID_SDK_ROOT`) to your SDK. |
| `inspect_ipa.py` returns `{"skipped": "otool, plutil and unzip are required (macOS with Xcode command line tools)"}` | Not on macOS, or Xcode command line tools are missing | Run on a Mac with `xcode-select --install`. Elsewhere, IPA checks stay `Not run`. |
| `check_pins.py` returns `{"skipped": "openssl not found (install OpenSSL to compute SPKI hashes)"}` | `--host` or `--chain` was used without `openssl` on `PATH` | Install OpenSSL. `--nsc` alone works without it. |
| `check_pins.py --host api.example.invalid` gives `live_match: null` for `sub.api.example.invalid`, or for the host's subdomains under `includeSubdomains="true"` | `--host` compares only the `<domain>` entry whose text exactly equals the host | Pass the domain exactly as written in the config. To check a subdomain, save its chain (`openssl s_client -connect sub.api.example.invalid:443 -servername sub.api.example.invalid -showcerts </dev/null > chain.pem`) and use `--chain chain.pem`, which compares every pinned domain. |
| `check_pins.py` shows a negative `days_left` | The `pin-set` `expiration` is in the past, so Android no longer enforces the pins | Report it as a finding (MASVS-NETWORK-2, MASWE-0028) and plan a pin rotation with the backend team. |
| `make_report.py` wrote `report.csv`, not `report.xlsx` | `openpyxl` isn't installed for the Python that ran it | `pip install openpyxl`, or use the CSV. |
| `scan_source.py` match has `status: unresolved` | The matched line uses a placeholder such as `${allowBackup}` | Resolve it from `manifestPlaceholders` (`defaultConfig` plus the release flavor) and report it as `inferred`, or check the merged manifest with `inspect_apk.py`. If it can't be resolved, record `Not run` ("unresolved placeholder: check merged manifest/APK"). |
| `skipped_rules` lists `FLT-STORAGE-2` with `pubspec.lock not found` | That rule only fires for old `flutter_secure_storage` versions and needs the lockfile to tell | Run `flutter pub get` to create `pubspec.lock`, or scan the folder that contains it. |
| Matches in `node_modules`, `Pods` or `.pub-cache` are missing | Dependency folders are skipped by default | Add `--include-deps`. Each match then has the owning package in `owner`. |
| A committed keystore isn't reported | Filename rules skip git-ignored paths, and the file may be ignored | Check with `git check-ignore -v <path>` and `git log --stat -- <path>`: an ignored file that was committed before is still in history. |
| A large or generated file isn't scanned | Files over 2 MB and binary files are skipped | Expected. Check those files by hand if they matter. |
| A script exits 2 with `{"error": "not a directory: ..."}` or `{"error": "not a file: ..."}` | Wrong path | Check the path; scripts take paths relative to the current directory. |
| `scan_source.py` returns `{"error": "unknown stack: ..."}` | `--stacks` has a name other than `android`, `ios`, `flutter`, `react-native` | Fix the list. |

## make_report.py errors and warnings

Errors exit with code 2 and `{"error": "invalid findings", "details": [...]}`. Fix each line in `details`, then run it again.

| Message (in `details`) | Cause | What to do |
|---|---|---|
| `$.findings[i]: missing required '<field>'` | A required field is missing (`title`, `control`, `asset`, `observation`, `severity`, `status`, `evidence_kind`) | Add it. |
| `$.findings[i].severity: '<value>' not one of [...]` (also `status`, `evidence_kind`) | A value outside the allowed list, e.g. status "Not exploitable" | Use one of the listed values. Put nuance in `response`. |
| `$...: expected <type>` | Wrong JSON type, e.g. `assets` as a string | Fix the type. |
| `$.findings[i].control: unknown control '<id>'` | Not a control ID in `data/controls.json`, or several IDs in one field | Use one ID such as `MASVS-STORAGE-2`. Split findings that need two controls. |
| `$.findings[i].maswe: unknown weakness '<id>' (not in data/maswe.json)` | A made-up or mistyped MASWE ID | Pick from the control's `maswe` list in `data/controls.json`, or leave `maswe` empty. |
| `status Fixed requires non-empty evidence with evidence_kind 'verified'` (also `Already mitigated`) | The fix hasn't been verified on a built artifact | Keep the row `Open` until it's re-verified. Don't fill in evidence that wasn't produced. |
| `status Fixed requires a non-empty retest_build` | No build recorded for the verification | Add the real build the fix was verified on. |
| `status False positive requires non-empty evidence with evidence_kind 'verified' or 'inferred', not manual` | A false positive with no attribution | Add the commands that attribute the match (owning package, unreachable code) with `evidence_kind: inferred`, or verify on the artifact. |
| `{"error": "cannot read findings", ...}` | The file is missing or isn't valid JSON | Check the path and the JSON syntax. |
| `make_report.py: error: the following arguments are required: ...` (plain text on stderr) | Missing `--out` or the findings path | `make_report.py <findings.json> --out <dir>`. |

Warnings don't stop the report:

| Message (in `warnings`) | Cause | What to do |
|---|---|---|
| `$.findings[i] (<title>): MASWE-NNNN maps to <controls>, not <control>` | The weakness isn't mapped to the finding's control in `data/maswe.json` | Change the control to one listed, or pick a weakness mapped to this control. Don't ignore it. |

## Maintainers

| Symptom | Cause | What to do |
|---|---|---|
| `scripts/package.sh` prints `skills/masvs/ has uncommitted changes; commit or stash them before packaging` | The release zip must match a commit | Commit or stash changes under `skills/masvs/`, then run it again. |
| `scripts/package.sh` fails with `zip: command not found` | `zip` isn't installed | Install `zip`. |
| `tests/test_references.py` denylist test is skipped | `MASVS_DENYLIST` isn't set | Run `MASVS_DENYLIST="word1,word2" .venv/bin/pytest -q tests/test_references.py` before a release. |
