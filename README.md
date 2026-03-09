# hacking-skills

Claude Code skills for finding bugs and vulnerabilities — bug bounty, pentest, CTF, code review.

## Structure

Categories are plain folders. Each technique is its own skill with its own `SKILL.md`.

```
.claude-plugin/
  marketplace.json              ← skill collections for distribution
skills/
  distill-to-skill/             ← meta-skill: generates new skills from any source
    SKILL.md
  <category>/                   ← plain folder, no SKILL.md
    <technique>/
      SKILL.md                  ← one skill per technique
      scripts/                  ← optional: helper scripts
      references/               ← optional: supplementary docs
      assets/                   ← optional: payloads, templates
```

## Skills

### Meta
| Skill | Description |
|-------|-------------|
| [distill-to-skill](skills/distill-to-skill/SKILL.md) | Extract reusable offensive knowledge from any source (bug report, blog, book, CTF, pentest report, ezine) → SKILL.md |

### Web Recon
| Skill | WSTG |
|-------|------|
| [web-fingerprinting](skills/web-recon/web-fingerprinting/SKILL.md) | INFO-01–10 |

### Authentication
| Skill | WSTG |
|-------|------|
| [auth-bypass](skills/authentication/auth-bypass/SKILL.md) | ATHN-01, 04–06 |
| [default-credentials](skills/authentication/default-credentials/SKILL.md) | ATHN-02, 07 |
| [password-reset-flaws](skills/authentication/password-reset-flaws/SKILL.md) | ATHN-07, 09 |

### Authorization
| Skill | WSTG |
|-------|------|
| [authz-bypass](skills/authorization/authz-bypass/SKILL.md) | ATHZ-02, 04 |
| [bola-idor](skills/authorization/bola-idor/SKILL.md) | ATHZ-04 |
| [path-traversal](skills/authorization/path-traversal/SKILL.md) | ATHZ-01 |

### Session
| Skill | WSTG |
|-------|------|
| [cookie-attacks](skills/session/cookie-attacks/SKILL.md) | SESS-02, 06 |
| [session-fixation](skills/session/session-fixation/SKILL.md) | SESS-01, 03, 04 |

### Injection
| Skill | WSTG |
|-------|------|
| [sql-injection](skills/injection/sql-injection/SKILL.md) | INPV-05 |
| [xss-reflected](skills/injection/xss-reflected/SKILL.md) | INPV-01 |
| [xss-stored](skills/injection/xss-stored/SKILL.md) | INPV-02 |
| [cmd-injection](skills/injection/cmd-injection/SKILL.md) | INPV-12 |
| [ssrf](skills/injection/ssrf/SKILL.md) | INPV-19 |
| [ssti](skills/injection/ssti/SKILL.md) | INPV-18 |
| [xxe](skills/injection/xxe/SKILL.md) | INPV-07 |
| [http-request-smuggling](skills/injection/http-request-smuggling/SKILL.md) | INPV-15 |

### Client-Side
| Skill | WSTG |
|-------|------|
| [clickjacking](skills/client-side/clickjacking/SKILL.md) | CLNT-09 |
| [cors-misconfig](skills/client-side/cors-misconfig/SKILL.md) | CLNT-07 |
| [csrf](skills/client-side/csrf/SKILL.md) | SESS-05 |
| [cspt](skills/client-side/cspt/SKILL.md) | blog_post |
| [dom-xss](skills/client-side/dom-xss/SKILL.md) | CLNT-01 |

### Web
| Skill | WSTG |
|-------|------|
| [business-logic-flaws](skills/web/business-logic-flaws/SKILL.md) | BUSL-01–06 |

### CI/CD
| Skill | Source |
|-------|--------|
| [github-actions-script-injection](skills/cicd/github-actions-script-injection/SKILL.md) | blog_post |
| [github-actions-cache-poisoning](skills/cicd/github-actions-cache-poisoning/SKILL.md) | blog_post |
| [pwn-request](skills/cicd/pwn-request/SKILL.md) | blog_post |
| [cicd-bot-command-injection](skills/cicd/cicd-bot-command-injection/SKILL.md) | blog_post |
| [self-hosted-runner-poisoning](skills/cicd/self-hosted-runner-poisoning/SKILL.md) | blog_post |

## Adding a New Skill

### From source material (recommended)
Paste any security content and run `/distill-to-skill`. Claude extracts the technique
and outputs a ready-to-save `SKILL.md` with the correct path and `marketplace.json` entry.

### Manually
1. Create `skills/<category>/<technique-name>/SKILL.md`
2. Ensure `name` in frontmatter matches the directory name exactly
3. Add the skill path to `.claude-plugin/marketplace.json`
