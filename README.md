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

### `owasp-wstg` — [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/stable/)

#### Web Recon
| Skill | WSTG | Source |
|-------|------|--------|
| [web-fingerprinting](skills/owasp-wstg/web-recon/web-fingerprinting/SKILL.md) | INFO-01–10 | [WSTG](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/README) |

#### Authentication
| Skill | WSTG | Source |
|-------|------|--------|
| [auth-bypass](skills/owasp-wstg/authentication/auth-bypass/SKILL.md) | ATHN-01, 04–06 | [WSTG](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/04-Authentication_Testing/README) |
| [default-credentials](skills/owasp-wstg/authentication/default-credentials/SKILL.md) | ATHN-02, 07 | [WSTG](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/04-Authentication_Testing/README) |
| [password-reset-flaws](skills/owasp-wstg/authentication/password-reset-flaws/SKILL.md) | ATHN-07, 09 | [WSTG](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/04-Authentication_Testing/README) |

#### Authorization
| Skill | WSTG | Source |
|-------|------|--------|
| [authz-bypass](skills/owasp-wstg/authorization/authz-bypass/SKILL.md) | ATHZ-02, 04 | [WSTG](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/05-Authorization_Testing/README) |
| [bola-idor](skills/owasp-wstg/authorization/bola-idor/SKILL.md) | ATHZ-04 | [WSTG](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/05-Authorization_Testing/README) |
| [path-traversal](skills/owasp-wstg/authorization/path-traversal/SKILL.md) | ATHZ-01 | [WSTG](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/05-Authorization_Testing/README) |

#### Session
| Skill | WSTG | Source |
|-------|------|--------|
| [cookie-attacks](skills/owasp-wstg/session/cookie-attacks/SKILL.md) | SESS-02, 06 | [WSTG](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/06-Session_Management_Testing/README) |
| [session-fixation](skills/owasp-wstg/session/session-fixation/SKILL.md) | SESS-01, 03, 04 | [WSTG](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/06-Session_Management_Testing/README) |

#### Injection
| Skill | WSTG | Source |
|-------|------|--------|
| [sql-injection](skills/owasp-wstg/injection/sql-injection/SKILL.md) | INPV-05 | [WSTG](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/README) |
| [xss-reflected](skills/owasp-wstg/injection/xss-reflected/SKILL.md) | INPV-01 | [WSTG](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/README) |
| [xss-stored](skills/owasp-wstg/injection/xss-stored/SKILL.md) | INPV-02 | [WSTG](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/README) |
| [cmd-injection](skills/owasp-wstg/injection/cmd-injection/SKILL.md) | INPV-12 | [WSTG](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/README) |
| [ssrf](skills/owasp-wstg/injection/ssrf/SKILL.md) | INPV-19 | [WSTG](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/README) |
| [ssti](skills/owasp-wstg/injection/ssti/SKILL.md) | INPV-18 | [WSTG](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/README) |
| [xxe](skills/owasp-wstg/injection/xxe/SKILL.md) | INPV-07 | [WSTG](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/README) |
| [http-request-smuggling](skills/owasp-wstg/injection/http-request-smuggling/SKILL.md) | INPV-15 | [WSTG](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/README) |

#### Client-Side
| Skill | WSTG | Source |
|-------|------|--------|
| [dom-xss](skills/owasp-wstg/client-side/dom-xss/SKILL.md) | CLNT-01 | [WSTG](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/11-Client-Side_Testing/README) |
| [csrf](skills/owasp-wstg/client-side/csrf/SKILL.md) | SESS-05 | [WSTG](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/06-Session_Management_Testing/README) |
| [cors-misconfig](skills/owasp-wstg/client-side/cors-misconfig/SKILL.md) | CLNT-07 | [WSTG](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/11-Client-Side_Testing/README) |
| [clickjacking](skills/owasp-wstg/client-side/clickjacking/SKILL.md) | CLNT-09 | [WSTG](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/11-Client-Side_Testing/README) |

#### Web
| Skill | WSTG | Source |
|-------|------|--------|
| [business-logic-flaws](skills/owasp-wstg/web/business-logic-flaws/SKILL.md) | BUSL-01–06 | [WSTG](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/10-Business_Logic_Testing/README) |

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
