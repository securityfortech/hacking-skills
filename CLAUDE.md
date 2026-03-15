# hacking-skills

## Picking an agent role

When the user starts an engagement, pick the right agent role and read its `AGENT.md` first:

- **Web app / API target** → `agents/webapp-pentester/AGENT.md`
- **Mobile app (Android/iOS)** → `agents/mobile-pentester/AGENT.md`
- **CI/CD / GitHub Actions** → `agents/cicd-auditor/AGENT.md`

The agent file tells you which skills to load and the engagement methodology to follow.

## Using the skills graph

When the user asks you to test, audit, pentest, find bugs, or hunt vulnerabilities on a target:

1. **Read `SKILLS_GRAPH.md` first** — it's the entry point to the skill network. It shows attack chains, topic clusters, and cross-domain patterns.
2. **Identify which clusters apply** to the target (web app, mobile, CI/CD, API, etc.).
3. **Follow the relevant [[wikilinks]]** into specific skill files for the techniques you'll actually use — don't load everything, just what's relevant.
4. **Use progressive disclosure**: graph index → cluster → skill description → full SKILL.md body.

This is the difference between following a checklist and understanding the domain.

## Logging and improving skills

- After any skill execution (success or failure): use `/observe-skill` to log the outcome.
- If a skill fails or underperforms: use `/amend-skill` to inspect its history and propose a fix.

## Adding new skills

Paste any source material (blog post, CVE, writeup, pentest report) and run `/distill-skill`.
It outputs a ready-to-save `SKILL.md` and the marketplace.json entry.
