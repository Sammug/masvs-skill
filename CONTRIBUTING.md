# Contributing

## Add a rule

1. **Entry in `masvs/data/rules.json`.** Add an object to `rules`. The `fields` block at the top of that file documents every key. Required: `id` (unique, `STACK-TOPIC-N`), `control` (an id from `masvs/data/controls.json`), `stacks` (or `"*"`), `files` (glob), `pattern`, `kind` (`smell`, `secret` or `config`) and `message`. Optional: `unresolved_pattern`, `absent`, `requires_in_file`, `unless_in_file`, `exclude_files`, `exclude_pattern`, `exists`, `requires`.
2. **Fixtures.** Add a positive and a negative case under `tests/fixtures/scan/<name>/` (the negative must look similar but be safe). Use synthetic values only.
3. **Test.** Add a test in `tests/test_scan_source.py` asserting the rule fires on the positive fixture (with the expected line) and not on the negative one.
4. **Playbook.** Mention the rule id in the relevant `masvs/references/<group>.md` playbook, with how to confirm it and the fix pattern. `tests/test_references.py` checks that every rule id referenced there exists.

## Run the suite

```bash
.venv/bin/pytest -q
```

## Denylist

No client data may ship in `masvs/`: no company or product names, hostnames, pins, ticket ids or bundle ids. Check with a comma-separated list of words to reject:

```bash
MASVS_DENYLIST="word1,word2" .venv/bin/pytest -q tests/test_references.py
```

Without `MASVS_DENYLIST` that test is skipped, so run it with your list before every release.

## No client data

Fixtures, evals and docs must use clearly synthetic names (`com.example.app`, `example.invalid`, `user_001`). Never paste real findings, builds, tokens or screenshots from an engagement. Keep answer keys for real audits in the audited repo, not here.

## Release

Bump `metadata.version` in `masvs/SKILL.md`, run the suite and denylist, then `scripts/package.sh`.
