# masvs

A Claude Code plugin for OWASP MASVS mobile security audits, pentest/VAPT prep and remediation of findings. It covers Flutter, native Android (Kotlin/Java), native iOS (Swift/ObjC) and React Native apps.

## What it does

| Mode | Use it to | Example prompt |
|---|---|---|
| `audit` | Scan the source and any APK/IPA, then write `findings.json`, a Markdown report and an optional .xlsx | "Audit this app for MASVS before the pentest" |
| `remediate` | Take an auditor's findings, map each to a MASVS control, classify it (fix, already mitigated, false positive), apply fixes and fill in the response columns | "Here is the VAPT sheet, respond to each finding and fix what's real" |
| `checklist` | Get a short per-feature checklist while coding | "I'm adding biometric login, what MASVS checks apply?" |

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

Ask in plain words, for example "run a MASVS audit of this app", or invoke it directly with `/masvs:masvs audit`. Reports go to `<app>/.masvs/` (add it to `.gitignore`).

## Requirements

- Python 3.9 or newer, standard library only at runtime.
- Optional: `openpyxl`, needed only for .xlsx output (CSV is written without it). The tests use it too.
- `openssl` for certificate checks.
- Android build-tools `aapt2` for APK checks (found automatically in the Android SDK).
- macOS `otool` and `plutil` for IPA checks.

A missing tool never fails a run. The script exits 0 with `{"skipped": "<reason>"}` and the report lists that check as `Not run`.

## Example output

An excerpt of `report.md` (fake data):

| Finding | MASVS Control | Severity | Status | Evidence |
|---|---|---|---|---|
| Backups enabled | MASVS-STORAGE-2 | Medium | Open | [verified] allow_backup: true in the built APK |
| Cleartext traffic allowed | MASVS-NETWORK-1 | Medium | Open | [inferred] debug network config only, release not checked |
| Plugin external-storage call | MASVS-STORAGE-1 | Info | False positive | [inferred] match is inside a third-party package |
| Root detection bypass | MASVS-RESILIENCE-1 | Medium | Not run | [manual] needs a device and a hooking test |

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

Content is based on OWASP MASVS, MASTG and MASWE (CC BY-SA 4.0), paraphrased, with control IDs cited. See `NOTICE`. The skill's own code is Apache-2.0 (`LICENSE`).

## Privacy

The scripts run locally and make no network calls, except `check_pins.py --host`, which connects to the host you name. Known token formats and long quoted literals are redacted to their first 4 characters in the JSON, Markdown and xlsx output.
