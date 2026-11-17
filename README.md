# masvs

A Claude Code plugin for OWASP MASVS mobile security audits, pentest/VAPT prep and remediation of findings. Every finding is mapped to a MASVS control (what to achieve) and an OWASP MASWE weakness (what went wrong). It covers Flutter, native Android (Kotlin/Java), native iOS (Swift/ObjC) and React Native apps.

## What it does

| Mode | Use it to | Example prompt |
|---|---|---|
| `audit` | Scan the source and any APK/IPA, then write `findings.json`, a Markdown report and an optional .xlsx | "Audit this app for MASVS before the pentest" |
| `remediate` | Take an auditor's findings, map each to a MASVS control and MASWE weakness, classify it (fix, already mitigated, false positive), apply fixes and fill in the response columns | "Here is the VAPT sheet, respond to each finding and fix what's real" |
| `checklist` | Get a short per-feature checklist, one item per MASWE weakness, while coding | "I'm adding biometric login on Flutter, what MASVS/MASWE checks apply?" |

## Install

In Claude Code, run:

```
/plugin install masvs --marketplace Sammug/masvs-skill
```

On Claude Code versions before 2.1.275, use two commands instead:

```
/plugin marketplace add Sammug/masvs-skill
/plugin install masvs@masvs-skill
```

Restart Claude Code (or start a new session) after installing.

**For a whole team:** commit this to an app's `.claude/settings.json`, and anyone who opens the repo in Claude Code is prompted to install the plugin:

```json
{
  "extraKnownMarketplaces": {
    "masvs-skill": { "source": { "source": "github", "repo": "Sammug/masvs-skill" } }
  },
  "enabledPlugins": { "masvs@masvs-skill": true }
}
```

**Without plugins:** download `masvs-<version>.zip` from [Releases](https://github.com/Sammug/masvs-skill/releases) and unzip it into `~/.claude/skills/` (every project) or `<app>/.claude/skills/` (one app).

## Use

Open your app's repo in Claude Code and ask in plain words. Claude picks the skill up on its own when you mention MASVS, MASWE, a pentest, VAPT or a security audit. To call it directly, type `/masvs:masvs` followed by your request (plain `/masvs` won't find it, because plugin skills are namespaced).

Reports go to `<app>/.masvs/`. Add that folder to `.gitignore`, because it holds security findings.

### Prompts that work well

Good prompts say three things: **the mode** (audit, remediate or checklist), **what to look at** (the repo, a built APK/IPA, the auditor's sheet) and **what you want back** (a report, fixes, responses).

**Audit before a pentest**

```
Run a MASVS audit of this app. The release APK is at build/app/outputs/flutter-apk/app-release.apk
and the IPA is at build/ios/ipa/MyApp.ipa. Write the report and an xlsx.
```

```
/masvs:masvs audit — Android only, no build yet. Tell me what can't be checked without an APK.
```

**Respond to an auditor's findings**

```
Here is the VAPT report: docs/security/vapt-round1.xlsx. For each finding, map it to a MASVS control
and MASWE weakness, decide fix / already mitigated / false positive with evidence, fix what is real,
and fill in the response columns.
```

```
The pentester says "Weak Cryptographic Implementation: AES-CBC with PKCS7 padding". Which MASWE
weakness is this, is it real in our code or in a plugin, and what should we reply?
```

**Checklist while building a feature**

```
I'm adding biometric login on Flutter. Give me the MASVS/MASWE checklist for Android and iOS,
with the fix pattern and the test to show an auditor.
```

**Questions**

```
Explain MASWE-0006 for a React Native app and show me how to check it in our build.
Which MASWE weaknesses fall under MASVS-NETWORK-1, and which ones do we fail?
```

**Tips**

- **Give it the built app when you can.** Without an APK or IPA, build-only checks come back as `Not run`, and nothing can be marked `Fixed` or `Already mitigated`.
- **Don't ask for a clean sheet.** The skill won't mark something fixed without verified evidence, even when asked. That protects you when the pentester retests.
- **Name the flavor or environment** (dev, UAT, prod) if your app has several. Settings often differ between them.
- **Say when a fix changes UX or the backend** (forced re-login, pin rotation). The skill proposes these and waits for your sign-off instead of applying them.

## Requirements

- Python 3.9 or newer, standard library only at runtime.
- Optional: `openpyxl`, needed only for .xlsx output (CSV is written without it). The tests use it too.
- `openssl` for certificate checks.
- Android build-tools `aapt2` for APK checks (found automatically in the Android SDK).
- macOS `otool` and `plutil` for IPA checks.

A missing tool never fails a run. The script exits 0 with `{"skipped": "<reason>"}` and the report lists that check as `Not run`.

## Example output

An excerpt of `report.md` (fake data):

| Finding | MASVS Control | MASWE | Severity | Status | Evidence |
|---|---|---|---|---|---|
| Backups enabled | MASVS-STORAGE-2 | MASWE-0006 (Sensitive Data Not Excluded From Backup) | Medium | Open | [verified] allow_backup: true in the built APK |
| Cleartext traffic allowed | MASVS-NETWORK-1 | MASWE-0026 (Network Traffic Not Encrypted) | Medium | Open | [inferred] debug network config only, release not checked |
| Plugin external-storage call | MASVS-STORAGE-1 | MASWE-0002 (Sensitive Data Stored Unencrypted Outside of Private Storage) | Info | False positive | [inferred] match is inside a third-party package |
| Root detection bypass | MASVS-RESILIENCE-1 | MASWE-0051 (Root/Jailbreak Detection Not Implemented) | Medium | Not run | [manual] needs a device and a hooking test |

## MASVS, MASWE and MASTG

- **MASVS** v2.1.0: the 24 controls a finding is filed under.
- **MASWE** v1.0.0: all 78 weaknesses, with requirement, modes of introduction and mitigations (`skills/masvs/data/maswe.json`). Scan rules carry a default MASWE ID, and `make_report.py` rejects unknown IDs and warns when an ID doesn't belong to the finding's control.
- **MASTG**: candidate tests per control, to read before citing.

## Evidence and pass/fail

Every status carries an evidence kind: `verified` (a script or command on a built artifact or live endpoint showed it), `inferred` (source, config or a scan showed it) or `manual` (nothing has exercised it yet).
`Fixed` and `Already mitigated` are only accepted with verified evidence; scan-only results stay `Open` or `Not run`.
The pass/fail mapping, severity scale and statuses are defined once in `skills/masvs/SKILL.md`.

## Updating

Plugin: run `/plugin marketplace update masvs-skill`, then restart Claude Code. Zip install: replace the `masvs/` folder with the one from the newer zip. The version is in `.claude-plugin/plugin.json` and in `metadata.version` in `skills/masvs/SKILL.md`.

## Tests and evals

```bash
python3 -m venv .venv && .venv/bin/pip install pytest openpyxl
.venv/bin/pytest -q
MASVS_DENYLIST="word1,word2" .venv/bin/pytest -q tests/test_references.py   # no client identifiers
scripts/package.sh                                                          # writes dist/masvs-<version>.zip
```

Pressure scenarios and fixtures for the skill itself are in `evals/` (see `evals/README.md`). To add a rule, see `CONTRIBUTING.md`.

## Attribution

Content is based on OWASP MASVS, MASTG and MASWE (CC BY-SA 4.0). Control summaries are paraphrased; the MASWE catalog quotes weakness titles and requirements. See `NOTICE`. The skill's own code is Apache-2.0 (`LICENSE`).

## Privacy

The scripts run locally and make no network calls, except `check_pins.py --host`, which connects to the host you name. Known token formats and long quoted literals are redacted to their first 4 characters in the JSON, Markdown and xlsx output.
