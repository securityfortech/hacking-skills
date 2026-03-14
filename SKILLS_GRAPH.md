# Skills Graph

A map of offensive security skills and the relationships between them. Use this as your entry point when an engagement starts — follow the chains that match the target's surface area.

---

## Attack Chains

### Web App Full Compromise

Start with [[web-fingerprinting]] to identify the stack and admin entry points. If a login form appears, attempt [[default-credentials]] before anything else, then [[auth-bypass]] using parameter tampering and forced browsing. A successful login on a predictable session token warrants [[session-fixation]] and [[cookie-attacks]] analysis. Once inside, [[bola-idor]] enumerates every resource the application manages, and [[business-logic-flaws]] covers price manipulation, workflow skip, and race conditions.

### Injection to RCE

[[sql-injection]] and [[cmd-injection]] share the same input validation failure class — start with SQLi probes and escalate to OS commands if `xp_cmdshell` or `LOAD_FILE` is available. [[ssti]] is the third path: when user input reaches a template engine, math expression evaluation confirms code execution capability. [[ssrf]] can pivot into any of these by reaching an internal service that is vulnerable to injection. [[xxe]] can chain into [[ssrf]] by using an `http://` SYSTEM entity.

### XSS Escalation Ladder

[[xss-reflected]] requires victim interaction; [[xss-stored]] fires automatically on page load for every viewer. Both feed into [[dom-xss]] when the reflected or stored content is subsequently processed by JavaScript sinks like `innerHTML` or `eval`. Any XSS on the same origin can be used to bypass SameSite and execute [[csrf]], making account takeover fully automated. [[cspt]] lands in DOM XSS sinks when a traversed fetch URL returns attacker-controlled content.

### CI/CD Supply Chain

[[pwn-request]] opens a pull request from a fork that checks out attacker code in a `pull_request_target` context. That code execution opportunity triggers [[github-actions-script-injection]] via `preinstall` scripts or `run:` steps that interpolate attacker-controlled context variables. The script injection pivots into [[github-actions-cache-poisoning]] by evicting legitimate cache entries and planting poisoned `node_modules`. On repositories using self-hosted runners, [[self-hosted-runner-poisoning]] amplifies the blast radius to persistent infrastructure access. [[cicd-bot-command-injection]] is an alternative trigger path via comment commands that invoke the same privileged workflow context.

### Mobile Auth Bypass Chain

[[mobile-network-security]] is the first check — intercept traffic to understand the API surface. If TLS pinning blocks the proxy, [[mobile-resilience]] controls are the obstacle; bypass root/jailbreak detection to enable dynamic instrumentation. With instrumentation running, [[mobile-auth-bypass]] hooks `BiometricPrompt` callbacks to simulate authentication success without hardware interaction. The credentials or tokens unlocked by auth bypass are then extractable via [[mobile-insecure-storage]] techniques.

---

## Topic MOCs

### Injection Cluster

The injection family starts at user input reaching an interpreter. [[sql-injection]] hits the database query parser. [[cmd-injection]] hits the OS shell. [[ssti]] hits the template engine. [[xxe]] hits the XML parser. [[ssrf]] makes the server itself the injection vector — the server's HTTP client is the interpreter being abused. [[http-request-smuggling]] exploits the disagreement between two HTTP parsers at the proxy and backend layer.

### Authentication and Session Cluster

[[auth-bypass]] is the entry point — it covers forced browsing, parameter tampering, and deserialization exploits. [[default-credentials]] is a shortcut subset. [[password-reset-flaws]] is an alternative bypass path through the reset workflow. Once authentication succeeds (legitimately or not), [[session-fixation]] and [[cookie-attacks]] govern the session token lifecycle from issuance through logout.

### Authorization Cluster

[[authz-bypass]] covers the broad class of horizontal and vertical access control failures. [[bola-idor]] is the most common concrete form — swapping object IDs without ownership validation. [[path-traversal]] is an authz bypass on the filesystem. In GraphQL applications, [[graphql-idor-via-introspection-leak]] maps the schema to identify every resolver that accepts an ID argument without ownership checks.

### Client-Side Cluster

[[csrf]] exploits browser automatic credential attachment. [[cors-misconfig]] enables reading authenticated responses cross-origin, which undermines CSRF token defenses. [[clickjacking]] is a user-tricked CSRF variant where the victim is manipulated into interacting with a hidden UI element. [[dom-xss]] operates entirely in the browser — payloads never touch the server. [[cspt]] redirects `fetch()` calls via path traversal to reach attacker-controlled endpoints.

### CI/CD Cluster

All five CI/CD skills form an interconnected attack chain. [[github-actions-script-injection]] is the code execution primitive. [[pwn-request]] and [[cicd-bot-command-injection]] are the two trigger mechanisms. [[github-actions-cache-poisoning]] is the persistence and privilege escalation technique. [[self-hosted-runner-poisoning]] is the infrastructure access layer that amplifies all of the above.

### Mobile Cluster

[[mobile-insecure-storage]] and [[mobile-weak-crypto]] address data-at-rest protection. [[mobile-network-security]] addresses data-in-transit. [[mobile-auth-bypass]] attacks the authentication gate. [[mobile-platform-interaction]] covers IPC attack surfaces — Intents, Content Providers, deep links, WebViews. [[mobile-code-quality]] covers code-level defects in the same components. [[mobile-resilience]] is the defender's last line — and the attacker's first obstacle.

---

## Cross-Domain Patterns

### Trust Boundary Exploitation

[[ssrf]], [[xxe]], and [[cors-misconfig]] all exploit trust boundaries — the server's privileged position in a network, the XML parser's trust of external entities, and the browser's same-origin trust model respectively. When you find one of these, probe the others: a server that has SSRF may also have an XML endpoint with XXE, and vice versa.

### Input-to-Interpreter

[[sql-injection]], [[cmd-injection]], [[ssti]], [[xss-reflected]], and [[xxe]] are all input-to-interpreter attacks. The probe methodology is the same: inject a canary that has a different meaning in the target language than in the surrounding string context. The bypass techniques (encoding, whitespace substitution, quote escaping) transfer across all of them.

### Mobile to Web Parity

[[mobile-auth-bypass]] maps directly to [[auth-bypass]] — the same callback-only vs. cryptographically-bound distinction applies. [[mobile-network-security]] failures parallel [[cors-misconfig]] — both involve looser-than-intended cross-origin trust on mobile backends. [[mobile-code-quality]] SQLite injection is [[sql-injection]] adapted for Android's `rawQuery` API.

### Recon Enabling Everything

[[web-fingerprinting]] is the only skill with no incoming edges — it is always the start. The stack it identifies determines which injection skills are relevant (PHP → SSTI with Twig, Java → XXE via DocumentBuilder, any CMS → [[default-credentials]]). [[graphql-idor-via-introspection-leak]] plays the same recon role for GraphQL APIs that fingerprinting plays for web stacks.
