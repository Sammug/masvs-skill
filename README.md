# masvs

A Claude Code skill for OWASP MASVS mobile security audits, pentest/VAPT prep and remediation of findings. It covers Flutter, native Android (Kotlin/Java), native iOS (Swift/ObjC) and React Native apps. Only the `masvs/` folder is shipped.

## What it does

| Mode | Use it to | Example prompt |
|---|---|---|
| `audit` | Scan the source and any APK/IPA, then write `findings.json`, a Markdown report and an optional .xlsx | "Audit this app for MASVS before the pentest" |
| `remediate` | Take an auditor's findings, map each to a MASVS control, classify it (fix, already mitigated, false positive), apply fixes and fill in the response columns | "Here is the VAPT sheet, respond to each finding and fix what's real" |
| `checklist` | Get a short per-feature checklist while coding | "I'm adding biometric login, what MASVS checks apply?" |

## Install

Personal (works in every project):

```bash
unzip masvs-0.1.0.zip -d ~/.claude/skills/
```

This gives `~/.claude/skills/masvs/SKILL.md`.

Per app (everyone who clones the repo gets it): unzip into `<app>/.claude/skills/` and commit the `masvs/` folder.

Org-wide (optional): upload the zip as a claude.ai organization skill, if your organization allows it.

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
The pass/fail mapping, severity scale and statuses are defined once in `masvs/SKILL.md`.

## Updating

Replace the `masvs/` folder with the new one from the zip. The version is in the `metadata.version` field of the `masvs/SKILL.md` frontmatter.

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
