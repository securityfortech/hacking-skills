# Observations

This folder records execution history for every skill. Each skill gets its own subfolder. Every time a skill is run on a real target, the outcome is appended to a log file in that subfolder.

## Structure

```
observations/
  <skill-name>/
    runs.md       ← append-only log of execution outcomes
```

Example:

```
observations/
  sql-injection/
    runs.md
  bola-idor/
    runs.md
  github-actions-script-injection/
    runs.md
```

## runs.md Format

Each entry in `runs.md` follows this structure:

```
---
date: YYYY-MM-DD
skill: <skill-name>
task: <one-line description of what was attempted>
outcome: success | partial | fail
what_worked: <what steps or payloads produced results>
what_failed: <what steps or payloads produced no results or errors>
errors: <any error messages or unexpected responses>
notes: <anything else relevant>
---
```

## How Entries Are Created

Use the `/observe-skill` meta-skill to log a run after any skill execution. Trigger it by saying:

- "log this run"
- "skill worked" / "skill failed"
- "this didn't work"
- Or just describe what happened after running a skill

The `/observe-skill` skill creates `observations/<skill-name>/runs.md` if it does not exist, then appends the new entry.

## How the Log Is Used

The `/amend-skill` meta-skill reads `observations/<skill-name>/runs.md` to detect patterns in failures. When a skill has 3 or more failures, or when you say "improve this skill" or "why does X keep failing", `/amend-skill` synthesizes the failure patterns and proposes a targeted amendment to the skill's `SKILL.md`.
