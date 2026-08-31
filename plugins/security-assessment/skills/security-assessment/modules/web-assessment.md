# Module: Web Assessment — Browser-Facing Surface

> **Load when** the system serves a browser UI.
> Covers the browser trust model. Server-side injection is in `repo-assessment.md`.

The browser is a shared execution environment the attacker also has code in. This module assesses the
controls that keep the application's origin, session and DOM separated from everything else.

## Hypothesis catalog

### WB-1 · DOM-based XSS
- **Statement**: attacker-controlled data reaches a DOM sink without encoding, entirely client-side —
  so no server-side review finds it.
- **Falsifier**: sinks receive only framework-escaped values; no `innerHTML`-family sink is fed from
  `location`, `postMessage`, `document.referrer`, or storage.
- **EV**: source→sink trace in client code (E2), including bundled dependencies.
- **Traps**: `location.hash`/`search` into `innerHTML` or a router; `postMessage` handlers with no
  `origin` check (check this specifically — it is frequently missing); `JSON.parse(localStorage…)`
  rendered as HTML; client-side templating; `eval`, `Function`, `setTimeout(string)`;
  `element.setAttribute('href', userValue)` allowing `javascript:`.
- CWE-79 · ASVS 5.3.3

### WB-2 · Content Security Policy
- **Statement**: CSP would not contain an XSS.
- **Falsifier**: a policy without `unsafe-inline`/`unsafe-eval` in `script-src`, using nonces or
  hashes, with `object-src 'none'` and `base-uri 'self'`.
- **EV**: the response header (E1) or its configuration (E2).
- **Traps**: CSP in `Report-Only` and never enforced; `unsafe-inline` (which negates script control);
  a wildcard or a CDN host that serves arbitrary user content (JSONP endpoints and unpkg-style CDNs
  are bypasses); missing `base-uri` (allowing base-tag injection); a `<meta>` CSP that misses headers.
- **Severity note**: a weak CSP is not itself a vulnerability. Rate it as **defence-in-depth**
  (typically Low/Informational) unless an XSS finding exists, in which case it raises that finding's
  impact. Reporting "missing CSP" as High is a credibility-losing false positive.
- CWE-1021 · ASVS 14.4.3

### WB-3 · Security headers and transport
- **Falsifier**: HSTS with an adequate max-age, `X-Content-Type-Options: nosniff`,
  `X-Frame-Options`/`frame-ancestors`, `Referrer-Policy`, and a restrictive `Permissions-Policy`.
- **Traps**: headers set in development config but stripped by the CDN or proxy in production;
  clickjacking protection missing on pages with state-changing actions specifically.
- **Severity note**: as with CSP — rate as hardening unless tied to a concrete attack.

### WB-4 · CSRF
- **Falsifier**: `SameSite=Lax`/`Strict` cookies **plus** a synchroniser token or an origin check on
  state-changing requests.
- **EV**: cookie attributes (E1/E2); CSRF middleware and its exemptions (E2).
- **Traps**: exemption lists that have grown (`@csrf_exempt`, `skip_before_action`); token validated
  on POST but not on PUT/DELETE; `SameSite=None` for a third-party embed; state-changing `GET`
  endpoints; JSON endpoints assumed safe (a `text/plain` content-type can make them form-submittable);
  a token that is not bound to the session.
- CWE-352 · ASVS 4.2.2

### WB-5 · Client-side secrets and data exposure
- **Statement**: the JavaScript bundle or the HTML contains something it should not.
- **Falsifier**: only public configuration in client code; no admin-only data in a server-rendered
  payload that a non-admin can receive.
- **EV**: grep the built bundle, not just the source (E2/E1).
- **Traps**: `NEXT_PUBLIC_`/`VITE_`/`REACT_APP_` prefixed secrets; source maps in production;
  hydration payloads (`__NEXT_DATA__`, `window.__INITIAL_STATE__`) carrying fields the UI hides;
  API responses returning full objects that the client filters for display; comments in HTML.
- **The "UI hides it" pattern is a real, frequent finding**: the server sends the data, the client
  chooses not to render it. Check the network payload, not the screen.
- CWE-200

### WB-6 · File upload
- **Falsifier**: content-type and magic-byte validation, extension allowlist, re-encoding or
  stripping of metadata, storage outside the web root or on a separate origin, generated filenames,
  and a size limit.
- **Traps**: SVG (executes script when served inline — serve as an attachment or re-encode); HTML/XML
  uploads; double extensions; `Content-Type` trusted from the client; files served from the app's own
  origin (any stored XSS then runs with the session); path traversal in the filename; image parsers
  with known CVEs (ImageMagick).
- CWE-434 · ASVS 12.1

### WB-7 · Origin isolation
- **Falsifier**: cookies scoped as tightly as possible; no wildcard `domain` attribute; separate
  origins for user content; `postMessage` handlers validating `origin`; `window.opener` neutralised.
- **Traps**: a cookie set on `.example.com` reachable by every subdomain, including one a customer
  controls or one that is dangling (subdomain takeover); `target="_blank"` without `rel="noopener"`;
  user content served from the app origin.

### WB-8 · Client-side authorization
- **Statement**: the UI is the only thing preventing an action.
- **Falsifier**: every capability the UI gates is independently enforced server-side.
- **EV**: for each UI-gated action, the corresponding server-side check (E2).
- This is the client-side view of `authz-assessment.md` AZ-2 — **route the finding there**; report
  the server-side gap, not the hidden button.

## Evidence collection

```bash
# headers, live (PASSIVE — a read-only GET against an authorized host)
curl -sSI https://<authorized-host>/ | grep -i -E 'content-security|strict-transport|x-frame|x-content-type|referrer-policy|permissions-policy|set-cookie'

# DOM sinks and sources
rg -n -e 'innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function|setTimeout\(\s*["'"'"']'
rg -n -e 'location\.(hash|search|href)|document\.referrer|postMessage|addEventListener\(\s*["'"'"']message'  -A5
# CSP / headers config
rg -n -i -e 'contentSecurityPolicy|Content-Security-Policy|helmet|strict-transport|X-Frame-Options'
# CSRF exemptions
rg -n -i -e 'csrf' -e 'csrf_exempt|skip_before_action.*verify_authenticity|CsrfViewMiddleware'
# client-side secrets — search the BUILD output
rg -n -e 'NEXT_PUBLIC_|VITE_|REACT_APP_|VUE_APP_' 
[ -d dist ] && rg -n -e 'sk_live|api[_-]?key|secret|password|BEGIN .*PRIVATE KEY' dist/ | head -20
fd -e map . dist build 2>/dev/null | head            # source maps shipped?
# uploads
rg -n -i -e 'multer|formidable|busboy|FileField|ActiveStorage|upload' -A6
```

Framework-specific: `security-audit/references/nextjs-security.md`, `web-testing.md`.

## Verification

- **Read the response, not the config.** Headers are added and removed by CDNs, proxies and edge
  middleware. A single authorized `curl -I` settles it; without one, the claim is E2 at best and
  must say so.
- Check the **built** bundle for secrets, not the source tree.
- For CSP, evaluate the actual policy string against known bypasses rather than checking presence.

## Common false positives

| Looks like | Actually |
|---|---|
| Missing security headers in code | Added at the CDN/edge — verify with a response |
| `innerHTML` | Fed a constant, or DOMPurify runs immediately before |
| `NEXT_PUBLIC_` variable | Genuinely public (a publishable key, an analytics ID) — check the vendor's key naming |
| No CSRF token | The API is token-authenticated via a header, not cookies — no ambient authority, no CSRF |
| Missing CSP | Real hardening gap, but **not** a High on its own |
