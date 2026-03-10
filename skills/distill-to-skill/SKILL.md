---
name: distill-to-skill
description: >
  Use when the user wants to extract reusable offensive security knowledge from
  any source and generate a SKILL.md file. Trigger on: "distill this",
  "extract skill from", "turn this into a skill", "generate skill from",
  "convert this report/blog/book/walkthrough into a skill", or when the user
  pastes raw security content (bug report, pentest report, CTF writeup, blog
  post, ezine, book chapter) and wants it transformed into structured hunting
  methodology.
license: MIT
compatibility: Designed for Claude Code.
metadata:
  category: meta
  version: "0.1"
  source_types: meta_skill
---

# Distill Security Content to Skill

You are a knowledge distiller. Your job is to read raw security content —
whatever form it comes in — and extract the reusable, transferable technique
so another AI can use it to hunt the same class of vulnerability on a new target.

## Repository Structure

Skills are organized by **knowledge source** first, then by category:

```
skills/
  owasp-wstg/               ← framework-derived: systematic, comprehensive coverage
    <category>/
      <technique>/SKILL.md
  research/                 ← one-shot research: blog posts, CVEs, bug bounty writeups
    <category>/
      <technique>/SKILL.md
```

**Choose the right bucket:**
- `owasp-wstg/` — if the source is the OWASP WSTG or another comprehensive security framework
- `research/` — if the source is a blog post, CVE write-up, bug bounty report, ezine, CTF walkthrough, or any one-shot research

Examples:
```
skills/owasp-wstg/injection/sql-injection/SKILL.md
skills/owasp-wstg/authorization/bola-idor/SKILL.md
skills/research/cicd/pwn-request/SKILL.md
skills/research/client-side/cspt/SKILL.md
```

## Understanding the Source

Different sources carry different signal. Adapt your extraction focus accordingly:

- **Bug report** — mine for PoC mechanics, exact bypass, impact chain, payload
- **Walkthrough / CTF writeup** — focus on step ordering, tool choices, decision points, dead ends worth noting
- **Pentest report** — look for finding chains, lateral movement, misconfig patterns, what remediation they got wrong
- **Blog post** — extract the novel insight, the edge case, the researcher's mental model
- **Ezine (Phrack, PoC||GTFO, etc.)** — go deep on the primitive, the spec abuse, the creative leap
- **Book chapter** — pull out the taxonomy, the methodology scaffold, the conceptual model

If the source type is not stated, infer it from tone and structure.
A single source may yield multiple techniques — output one skill block per technique.

## Output Format

For each technique, generate one complete `SKILL.md`:

~~~
---
name: <technique-slug>
# Must match the parent directory name exactly.
# Lowercase letters, numbers, hyphens only. No leading/trailing/consecutive hyphens. Max 64 chars.
description: >
  <Trigger-heavy. Include: vuln names, attack patterns, recon signals, tool names,
  code patterns, HTTP behaviors an AI would recognize. Max 1024 chars.>
license: MIT
compatibility: Designed for Claude Code. <list any required tools e.g. Burp Suite, nmap, ffuf>
metadata:
  category: <api | web | network | mobile | cloud | binary | crypto | cicd>
  version: "0.1"
  source: <URL or reference of the source material>
  source_types: <bug_report | walkthrough | pentest_report | blog_post | ezine | book>
---

# <Technique Full Name>

## What Is Broken and Why
<1 paragraph. What assumption is violated. What an attacker gains.>

## Key Signals
<Indicators in HTTP responses, source code, configs, error messages, timing, behavior>

## Methodology
<Numbered steps. Concrete. Tool-agnostic where possible.>

## Payloads & Tools
<Specific payloads and commands. Use placeholders: TARGET, CALLBACK, VICTIM, TOKEN, APIKEY>

## Bypass Techniques
<Filter bypass, WAF evasion, encoding tricks, parameter pollution>

## Exploitation Scenarios
<2-3 anonymized scenarios. Format: Setup → Trigger → Impact>

## False Positives
<Patterns that look like this vuln but aren't — saves wasted triage time>

## Fix Patterns
<What remediation looks like in code or config. Confirms the real vuln.>
~~~

## Anonymization Rules

Strip everything traceable before writing output:
- No real URLs, domains, IPs, email addresses
- No program names, company names, author names, usernames
- No CVE numbers unless describing a generic class (e.g. "deserialization CVEs")
- Use placeholders: `TARGET`, `CALLBACK`, `VICTIM`, `TOKEN`, `APIKEY`

## Quality Rules

- If the source is thin on a section, write `N/A — not observed in source` rather than inventing content
- Focus on what is transferable to a new target, not what was specific to this report
- Concrete beats comprehensive — a working payload beats a paragraph of theory
- Keep each SKILL.md under 200 lines

## After Generating Output

Tell the user:
1. The full save path for each skill: `skills/owasp-wstg/<category>/<technique-slug>/SKILL.md` or `skills/research/<category>/<technique-slug>/SKILL.md`
2. The entry to add to `.claude-plugin/marketplace.json` under the `owasp-wstg` or `research` plugin collection
3. Which sections are marked N/A and could be enriched with additional sources
