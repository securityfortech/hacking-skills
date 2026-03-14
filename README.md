# hacking-skills

Claude Code skills for finding bugs and vulnerabilities — bug bounty, pentest, CTF, code review.

## Structure

```
.claude-plugin/
  marketplace.json              ← plugin collections for distribution
skills/
  meta/                         ← skill generation and self-improvement tooling
    distill-skill/
    observe-skill/
    amend-skill/
  web/                          ← web application security
    recon/
    auth/
    session/
    authz/
    injection/
    client-side/
    logic/
  mobile/                       ← mobile security (Android + iOS)
    storage/
    crypto/
    auth/
    network/
    platform/
    code/
    resilience/
  cicd/                         ← CI/CD pipeline security
```

## Skills Graph

[`SKILLS_GRAPH.md`](SKILLS_GRAPH.md) — a map of content (MOC) showing attack chains, topic clusters, and cross-domain patterns. Start here when you need to plan a testing approach or understand how skills relate to each other.

## Plugin Collections

| Collection | Skills | Description |
|------------|--------|-------------|
| `web` | 28 | Web application security — recon, auth, session, authz, injection, client-side, logic |
| `mobile` | 7 | Mobile security methodology (Android + iOS) — install for mobile coverage |
| `cicd` | 5 | CI/CD pipeline attack techniques — install for supply chain testing |
| `meta` | [`/distill-skill`](skills/meta/distill-skill/SKILL.md), [`/observe-skill`](skills/meta/observe-skill/SKILL.md), [`/amend-skill`](skills/meta/amend-skill/SKILL.md) | Skill generation, run logging, and self-improvement |

---

## Skills

### Meta
| Skill | Description |
|-------|-------------|
| [distill-skill](skills/meta/distill-skill/SKILL.md) | Extract reusable offensive knowledge from any source → SKILL.md |
| [observe-skill](skills/meta/observe-skill/SKILL.md) | Log skill run outcomes to `observations/<skill-name>/runs.md` |
| [amend-skill](skills/meta/amend-skill/SKILL.md) | Inspect failure history and propose targeted amendments to a skill |

---

### `web` — Web Application Security

#### Recon
| Skill | Source |
|-------|--------|
| [web-fingerprinting](skills/web/recon/web-fingerprinting/SKILL.md) | [WSTG INFO-01–10](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/README) |

#### Auth
| Skill | Source |
|-------|--------|
| [auth-bypass](skills/web/auth/auth-bypass/SKILL.md) | [WSTG ATHN-01, 04–06](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/04-Authentication_Testing/README) |
| [default-credentials](skills/web/auth/default-credentials/SKILL.md) | [WSTG ATHN-02, 07](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/04-Authentication_Testing/README) |
| [password-reset-flaws](skills/web/auth/password-reset-flaws/SKILL.md) | [WSTG ATHN-07, 09](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/04-Authentication_Testing/README) |
| [jwt-misconfig](skills/web/auth/jwt-misconfig/SKILL.md) | [VibeSec](https://github.com/BehiSecc/VibeSec-Skill) |

#### Session
| Skill | Source |
|-------|--------|
| [cookie-attacks](skills/web/session/cookie-attacks/SKILL.md) | [WSTG SESS-02, 06](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/06-Session_Management_Testing/README) |
| [session-fixation](skills/web/session/session-fixation/SKILL.md) | [WSTG SESS-01, 03, 04](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/06-Session_Management_Testing/README) |

#### Authz
| Skill | Source |
|-------|--------|
| [authz-bypass](skills/web/authz/authz-bypass/SKILL.md) | [WSTG ATHZ-02, 04](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/05-Authorization_Testing/README) |
| [bola-idor](skills/web/authz/bola-idor/SKILL.md) | [WSTG ATHZ-04](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/05-Authorization_Testing/README) |
| [path-traversal](skills/web/authz/path-traversal/SKILL.md) | [WSTG ATHZ-01](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/05-Authorization_Testing/README) |
| [mass-assignment](skills/web/authz/mass-assignment/SKILL.md) | [VibeSec](https://github.com/BehiSecc/VibeSec-Skill) |

#### Injection
| Skill | Source |
|-------|--------|
| [sql-injection](skills/web/injection/sql-injection/SKILL.md) | [WSTG INPV-05](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/README) |
| [xss-reflected](skills/web/injection/xss-reflected/SKILL.md) | [WSTG INPV-01](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/README) |
| [xss-stored](skills/web/injection/xss-stored/SKILL.md) | [WSTG INPV-02](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/README) |
| [cmd-injection](skills/web/injection/cmd-injection/SKILL.md) | [WSTG INPV-12](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/README) |
| [ssrf](skills/web/injection/ssrf/SKILL.md) | [WSTG INPV-19](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/README) |
| [ssti](skills/web/injection/ssti/SKILL.md) | [WSTG INPV-18](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/README) |
| [xxe](skills/web/injection/xxe/SKILL.md) | [WSTG INPV-07](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/README) |
| [http-request-smuggling](skills/web/injection/http-request-smuggling/SKILL.md) | [WSTG INPV-15](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/README) |

#### Client-Side
| Skill | Source |
|-------|--------|
| [dom-xss](skills/web/client-side/dom-xss/SKILL.md) | [WSTG CLNT-01](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/11-Client-Side_Testing/README) |
| [csrf](skills/web/client-side/csrf/SKILL.md) | [WSTG SESS-05](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/06-Session_Management_Testing/README) |
| [cors-misconfig](skills/web/client-side/cors-misconfig/SKILL.md) | [WSTG CLNT-07](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/11-Client-Side_Testing/README) |
| [clickjacking](skills/web/client-side/clickjacking/SKILL.md) | [WSTG CLNT-09](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/11-Client-Side_Testing/README) |
| [cspt](skills/web/client-side/cspt/SKILL.md) | [matanber.com](https://matanber.com/blog/cspt-levels) |
| [open-redirect](skills/web/client-side/open-redirect/SKILL.md) | [VibeSec](https://github.com/BehiSecc/VibeSec-Skill) |

#### Logic
| Skill | Source |
|-------|--------|
| [business-logic-flaws](skills/web/logic/business-logic-flaws/SKILL.md) | [WSTG BUSL-01–06](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/10-Business_Logic_Testing/README) |
| [insecure-file-upload](skills/web/logic/insecure-file-upload/SKILL.md) | [VibeSec](https://github.com/BehiSecc/VibeSec-Skill) |
| [graphql-idor-via-introspection-leak](skills/web/logic/graphql-idor-via-introspection-leak/SKILL.md) | manual |

---

### `mobile` — [OWASP Mobile Application Security Testing Guide](https://mas.owasp.org/MASTG/)

| Skill | MASVS | Source |
|-------|-------|--------|
| [mobile-insecure-storage](skills/mobile/storage/mobile-insecure-storage/SKILL.md) | MASVS-STORAGE-1, 2 | [MASTG](https://mas.owasp.org/MASTG/) |
| [mobile-weak-crypto](skills/mobile/crypto/mobile-weak-crypto/SKILL.md) | MASVS-CRYPTO-1, 2 | [MASTG](https://mas.owasp.org/MASTG/) |
| [mobile-auth-bypass](skills/mobile/auth/mobile-auth-bypass/SKILL.md) | MASVS-AUTH-1, 2, 3 | [MASTG](https://mas.owasp.org/MASTG/) |
| [mobile-network-security](skills/mobile/network/mobile-network-security/SKILL.md) | MASVS-NETWORK-1, 2 | [MASTG](https://mas.owasp.org/MASTG/) |
| [mobile-platform-interaction](skills/mobile/platform/mobile-platform-interaction/SKILL.md) | MASVS-PLATFORM-1, 2, 3 | [MASTG](https://mas.owasp.org/MASTG/) |
| [mobile-code-quality](skills/mobile/code/mobile-code-quality/SKILL.md) | MASVS-CODE-1, 2, 3, 4 | [MASTG](https://mas.owasp.org/MASTG/) |
| [mobile-resilience](skills/mobile/resilience/mobile-resilience/SKILL.md) | MASVS-RESILIENCE-1, 2, 3, 4 | [MASTG](https://mas.owasp.org/MASTG/) |

---

### `cicd` — CI/CD Pipeline Security

| Skill | Source |
|-------|--------|
| [github-actions-script-injection](skills/cicd/github-actions-script-injection/SKILL.md) | [adnanthekhan.com](https://adnanthekhan.com/posts/angular-compromise-through-dev-infra/) |
| [github-actions-cache-poisoning](skills/cicd/github-actions-cache-poisoning/SKILL.md) | [adnanthekhan.com](https://adnanthekhan.com/posts/angular-compromise-through-dev-infra/) |
| [pwn-request](skills/cicd/pwn-request/SKILL.md) | [landh.tech](https://www.landh.tech/blog/20251003-36m-installs/) |
| [cicd-bot-command-injection](skills/cicd/cicd-bot-command-injection/SKILL.md) | [landh.tech](https://www.landh.tech/blog/20251003-36m-installs/) |
| [self-hosted-runner-poisoning](skills/cicd/self-hosted-runner-poisoning/SKILL.md) | [adnanthekhan.com](https://adnanthekhan.com/2023/12/20/one-supply-chain-attack-to-rule-them-all/) |

---

## Adding a New Skill

### From source material (recommended)
Paste any security content and run `/distill-skill`. Claude extracts the technique,
outputs a ready-to-save `SKILL.md`, and tells you which collection to add it to.

### Manually
1. Choose the right bucket: `web/` for web vulnerabilities, `mobile/` for mobile, `cicd/` for CI/CD pipeline attacks, `meta/` for tooling
2. Create `skills/<bucket>/<category>/<technique>/SKILL.md`
3. Ensure `name` matches the directory name exactly
4. Add the path to `.claude-plugin/marketplace.json`
