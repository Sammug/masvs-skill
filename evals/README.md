# Skill evals

`scenarios.md` holds pressure scenarios for the `masvs` skill; each has a minimal fixture under `fixtures/<n>-<slug>/`.

To run one scenario:

1. Start a fresh agent (no prior context) in a scratch project, give it the preamble from `scenarios.md`, the fixture path and the scenario's **Prompt** verbatim.
2. Run it twice: once **without** the skill (baseline/RED) and once **with** it installed (symlink `masvs/` into the scratch project's `.claude/skills/`).
3. Grade each transcript and any files it wrote against **Expected behaviour**: every bullet must hold. Record baseline failures (and the agent's rationalisations, verbatim) to drive SKILL.md wording.
4. Fixtures are throwaway: copy them to the scratch project first so agent edits don't touch this repo.
