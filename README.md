# hacking-skills

Claude Code skills for finding bugs and vulnerabilities — bug bounty, pentest, CTF, code review.

## Structure

Skills are organized by **knowledge source**, not just vulnerability category.

```
.claude-plugin/
  marketplace.json              ← plugin collections for distribution
skills/
  distill-to-skill/             ← meta-skill: generate new skills from any source
  owasp-wstg/                   ← systematic framework: OWASP Web Security Testing Guide
    authentication/
    authorization/
    session/
    injection/
    client-side/
    web-recon/
    web/
  research/                     ← tactical: blog posts, CVEs, bug bounty writeups
    cicd/
    api-hacking/
    client-side/
```

## Plugin Collections

| Collection | Description |
|------------|-------------|
| `owasp-wstg` | Systematic web testing methodology — install for complete coverage mindset |
| `research` | Cutting-edge tactical techniques — install for specific attack patterns |
| `meta-skills` | Skill generation tooling |

---

## Skills

### Meta
| Skill | Description |
|-------|-------------|
| [distill-to-skill](skills/distill-to-skill/SKILL.md) | Extract reusable offensive knowledge from any source → SKILL.md |

---

### `owasp-wstg` — OWASP Web Security Testing Guide

#### Web Recon
| Skill | WSTG |
|-------|------|
| [web-fingerprinting](skills/owasp-wstg/web-recon/web-fingerprinting/SKILL.md) | INFO-01–10 |

#### Authentication
| Skill | WSTG |
|-------|------|
| [auth-bypass](skills/owasp-wstg/authentication/auth-bypass/SKILL.md) | ATHN-01, 04–06 |
| [default-credentials](skills/owasp-wstg/authentication/default-credentials/SKILL.md) | ATHN-02, 07 |
| [password-reset-flaws](skills/owasp-wstg/authentication/password-reset-flaws/SKILL.md) | ATHN-07, 09 |

#### Authorization
| Skill | WSTG |
|-------|------|
| [authz-bypass](skills/owasp-wstg/authorization/authz-bypass/SKILL.md) | ATHZ-02, 04 |
| [bola-idor](skills/owasp-wstg/authorization/bola-idor/SKILL.md) | ATHZ-04 |
| [path-traversal](skills/owasp-wstg/authorization/path-traversal/SKILL.md) | ATHZ-01 |

#### Session
| Skill | WSTG |
|-------|------|
| [cookie-attacks](skills/owasp-wstg/session/cookie-attacks/SKILL.md) | SESS-02, 06 |
| [session-fixation](skills/owasp-wstg/session/session-fixation/SKILL.md) | SESS-01, 03, 04 |

#### Injection
| Skill | WSTG |
|-------|------|
| [sql-injection](skills/owasp-wstg/injection/sql-injection/SKILL.md) | INPV-05 |
| [xss-reflected](skills/owasp-wstg/injection/xss-reflected/SKILL.md) | INPV-01 |
| [xss-stored](skills/owasp-wstg/injection/xss-stored/SKILL.md) | INPV-02 |
| [cmd-injection](skills/owasp-wstg/injection/cmd-injection/SKILL.md) | INPV-12 |
| [ssrf](skills/owasp-wstg/injection/ssrf/SKILL.md) | INPV-19 |
| [ssti](skills/owasp-wstg/injection/ssti/SKILL.md) | INPV-18 |
| [xxe](skills/owasp-wstg/injection/xxe/SKILL.md) | INPV-07 |
| [http-request-smuggling](skills/owasp-wstg/injection/http-request-smuggling/SKILL.md) | INPV-15 |

#### Client-Side
| Skill | WSTG |
|-------|------|
| [dom-xss](skills/owasp-wstg/client-side/dom-xss/SKILL.md) | CLNT-01 |
| [csrf](skills/owasp-wstg/client-side/csrf/SKILL.md) | SESS-05 |
| [cors-misconfig](skills/owasp-wstg/client-side/cors-misconfig/SKILL.md) | CLNT-07 |
| [clickjacking](skills/owasp-wstg/client-side/clickjacking/SKILL.md) | CLNT-09 |

#### Web
| Skill | WSTG |
|-------|------|
| [business-logic-flaws](skills/owasp-wstg/web/business-logic-flaws/SKILL.md) | BUSL-01–06 |

---

### `research` — Blog Posts, CVEs, Bug Bounty Writeups

#### CI/CD
| Skill | Source |
|-------|--------|
| [github-actions-script-injection](skills/research/cicd/github-actions-script-injection/SKILL.md) | [adnanthekhan.com](https://adnanthekhan.com/posts/angular-compromise-through-dev-infra/) |
| [github-actions-cache-poisoning](skills/research/cicd/github-actions-cache-poisoning/SKILL.md) | [adnanthekhan.com](https://adnanthekhan.com/posts/angular-compromise-through-dev-infra/) |
| [pwn-request](skills/research/cicd/pwn-request/SKILL.md) | [landh.tech](https://www.landh.tech/blog/20251003-36m-installs/) |
| [cicd-bot-command-injection](skills/research/cicd/cicd-bot-command-injection/SKILL.md) | [landh.tech](https://www.landh.tech/blog/20251003-36m-installs/) |
| [self-hosted-runner-poisoning](skills/research/cicd/self-hosted-runner-poisoning/SKILL.md) | [adnanthekhan.com](https://adnanthekhan.com/2023/12/20/one-supply-chain-attack-to-rule-them-all/) |

#### API Hacking
| Skill | Source |
|-------|--------|
| [graphql-idor-via-introspection-leak](skills/research/api-hacking/graphql-idor-via-introspection-leak/SKILL.md) | manual |

#### Client-Side
| Skill | Source |
|-------|--------|
| [cspt](skills/research/client-side/cspt/SKILL.md) | [matanber.com](https://matanber.com/blog/cspt-levels) |

---

## Adding a New Skill

### From source material (recommended)
Paste any security content and run `/distill-to-skill`. Claude extracts the technique,
outputs a ready-to-save `SKILL.md`, and tells you which collection to add it to.

### Manually
1. Choose the right bucket: `owasp-wstg/` for framework-derived, `research/` for one-shot research
2. Create `skills/<bucket>/<category>/<technique>/SKILL.md`
3. Ensure `name` matches the directory name exactly
4. Add the path to `.claude-plugin/marketplace.json`
