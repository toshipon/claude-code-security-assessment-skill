# Module: Authentication Assessment

> **Load when** the system has login, sessions, tokens, API keys, or SSO.
> Pairs with `authz-assessment.md` — authentication says *who you are*, authorization says *what you may do*.

Authentication failures are usually protocol or lifecycle failures, not missing-code failures. The
login form is fine; the reset flow, the token refresh, or the SSO assertion validation is not.

## Hypothesis catalog

### AU-1 · Session management
- **Statement**: a session can be stolen, fixed, or outlived by an attacker.
- **Falsifier**: session ID regenerated on every privilege change, cryptographically random, cookie
  `HttpOnly` + `Secure` + `SameSite`, absolute and idle timeouts, server-side invalidation on logout.
- **EV**: session config (E2/E4); a real `Set-Cookie` header (E1); the logout handler (E2).
- **Traps**: session **not** regenerated after login (fixation); logout that only clears the client
  cookie; "remember me" tokens that never expire; sessions surviving a password change.
- CWE-384, CWE-613 · ASVS 3.2, 3.3

### AU-2 · Password policy and storage
- **Statement**: passwords are weak enough, or stored weakly enough, to be recovered at scale.
- **Falsifier**: a modern KDF with sound parameters (argon2id, scrypt, bcrypt cost ≥ 12, PBKDF2 with
  a high iteration count), a length-based policy with a breached-password check, no composition rules
  that reduce entropy.
- **EV**: the hashing call and its parameters (E2); the registration/change validators (E2).
- **Traps**: `md5`/`sha1`/`sha256` without a KDF; a global static salt; a low bcrypt cost inherited
  from a tutorial; a maximum length that reveals plaintext storage or truncation.
- CWE-916, CWE-521 · ASVS 2.1, 2.4 · NIST SP 800-63B

### AU-3 · MFA
- **Statement**: MFA can be bypassed or is not enforced where it matters.
- **Falsifier**: MFA verified server-side on the session *before* any authenticated capability, and
  enforced on every authentication path.
- **EV**: the MFA verification step and what it mutates (E2); every login path (password, SSO,
  API key, mobile, legacy) (E2).
- **Traps**: MFA checked on a route the client is trusted to call; a partially-authenticated session
  that already carries privileges; MFA skipped for OAuth/API-key/mobile paths; unlimited OTP attempts;
  OTPs that stay valid after use or for far too long; MFA reset via email alone.
- CWE-287 · ASVS 2.8

### AU-4 · Password reset
- **Statement**: an attacker can take over an account through the reset flow. **Highest-yield
  authentication surface — assess it end-to-end, every time.**
- **Falsifier**: high-entropy single-use token, short expiry, bound to the user, invalidated on use
  and on password change, delivered only to the registered address, and all sessions revoked after use.
- **EV**: token generation (E2), storage (E2), validation (E2), the email construction (E2).
- **Traps**: token derived from user ID/timestamp/`Math.random`; token compared with `==` allowing
  timing or type-juggling attacks; token not invalidated after use; reset link built from a
  **`Host` header** the attacker controls (host-header poisoning — check this specifically); the
  response distinguishing existing from non-existent accounts; reset not revoking active sessions.
- CWE-640 · ASVS 2.5

### AU-5 · Account enumeration
- **Statement**: an attacker can determine whether an address is registered.
- **Falsifier**: identical response body, status code **and timing** for existing and non-existent
  accounts across login, reset, registration and invitation.
- **EV**: the response paths for both cases (E2); measured timings if authorized (E1).
- **Traps**: distinct error strings; registration rejecting a duplicate address; a timing difference
  because the password hash is only computed for existing users (compute a dummy hash either way).
- **Severity note**: usually Low alone — but it raises `E` for credential stuffing and for AU-4, so
  rate it in combination rather than in isolation.
- CWE-204 · ASVS 2.2.1

### AU-6 · Token handling
- **Statement**: a token can be stolen, replayed, or used past its intended life.
- **Falsifier**: short-lived access tokens, refresh rotation with reuse detection, server-side
  revocation, storage that JavaScript cannot read where the threat model requires it.
- **EV**: issuance, storage, refresh and revocation code (E2); token lifetimes (E2/E4).
- **Traps**: tokens in `localStorage` when XSS is in scope; tokens in URLs (they reach logs, proxies
  and `Referer`); refresh tokens that never rotate; no revocation path at all; API keys with no
  expiry, no scope and no rotation.
- CWE-522 · ASVS 3.5

### AU-7 · OAuth / OIDC
- **Statement**: the OAuth flow can be abused to obtain another user's session.
- **Falsifier**: exact-match redirect URI allowlist, `state` bound to the session and verified, PKCE
  on public clients, `nonce` verified, the ID token validated (`iss`, `aud`, `exp`, signature via
  JWKS), and account linking that requires proof of control of the email.
- **EV**: the client config and the callback handler (E2); redirect URI registration (E4).
- **Traps**: wildcard or prefix-matched redirect URIs; `state` generated but never verified;
  implicit flow still enabled; **account linking on unverified email** — the classic full takeover:
  sign up with the victim's address at an IdP that does not verify it, then link.
- CWE-601, CWE-352 · ASVS 2.11

### AU-8 · JWT validation
- **Statement**: a forged or altered JWT is accepted.
- **Falsifier**: algorithm pinned server-side, signature verified against a key the client cannot
  influence, `exp`/`nbf`/`iss`/`aud` all checked, `kid` resolved against a fixed key set.
- **EV**: the verification call and its options (E2); the library and its resolved version (E2).
- **Traps**: `alg: none` accepted; RS256→HS256 confusion using the public key as an HMAC secret;
  `decode()` used where `verify()` was meant (`jwt.decode`, `jsonwebtoken.decode`, `jose` without a
  key); `kid` taken from the token to fetch a key by path or URL; no expiry check; a weak HMAC secret
  committed to the repo; a token accepted from a different issuer or audience.
- CWE-347 · ASVS 3.5.3

### AU-9 · Credential exposure
- **Statement**: credentials are recoverable from somewhere an attacker can read.
- **Falsifier**: no credentials in source, history, logs, error responses, client bundles, or CI output.
- **EV**: see `secrets-crypto-assessment.md`; git history included.
- **Traps**: passwords or tokens in request/response logs; credentials in error messages;
  `NEXT_PUBLIC_`/`VITE_`/`REACT_APP_` prefixed secrets shipped to the browser; default accounts left
  enabled; a `.env` committed then deleted (still in history, still valid).
- CWE-522, CWE-798

### AU-10 · Rate limiting and lockout
- **Statement**: credential stuffing or brute force is not meaningfully constrained.
- **Falsifier**: per-account and per-IP limits with backoff, applied to *every* authentication path,
  enforced server-side (gateway or application) rather than client-side.
- **EV**: rate-limit configuration and where it applies (E2/E4).
- **Traps**: limits on `/login` but not on `/api/token`, the mobile endpoint, the GraphQL mutation,
  or the reset flow; per-IP only (defeated by rotation); lockout that enables account-denial abuse.
- CWE-307 · ASVS 2.2.1

## Evidence collection

```bash
# stack identification — then read THAT library's docs for the installed version
rg -n -i -e 'passport|next-auth|authjs|lucia|devise|omniauth|authlib|python-social|spring-security' \
        -e 'jsonwebtoken|jose|pyjwt|jwt-go|golang-jwt|ruby-jwt' -e 'cognito|auth0|okta|keycloak|firebase-auth|clerk|supabase'

# session and cookie config
rg -n -i -e 'httpOnly|sameSite|secure:|cookie\(|session\(|maxAge|expires'
# password hashing
rg -n -i -e 'bcrypt|argon2|scrypt|pbkdf2|hashpw|createHash|digest\(|md5|sha1'
# jwt verification — inspect every call's options
rg -n -e 'verify\(|decode\(|jwtVerify|createRemoteJWKSet|algorithms' -A5
# reset flow, host header, token generation
rg -n -i -e 'reset|forgot' -A6 | rg -n -i -e 'token|host|url'
rg -n -e 'Math\.random|random\.random|rand\(|uuid1\(' # non-CSPRNG in a security context
# oauth callback
rg -n -i -e 'redirect_uri|state|nonce|code_verifier|pkce' -A4
```

## Verification

- **Read the library's own security documentation for the resolved version.** Authentication libraries
  change defaults between majors, and this is where memory-based claims go wrong.
- Trace **every** authentication path, not just the web login: mobile, API keys, service-to-service,
  SSO, legacy endpoints, impersonation. A control applied to one path is not applied to the others.
- For the reset flow, write out all six steps (request → token → email → link → validation →
  invalidation) and check each. Bugs live in steps 5 and 6.

## Common false positives

| Looks like | Actually |
|---|---|
| No rate limiting in code | Enforced at the gateway/WAF/CDN — **verify it covers this exact path**, then treat as mitigating |
| `jwt.decode()` | Used for non-security purposes (logging, an unauthenticated hint) after a real `verify()` upstream |
| Weak-looking hash | Used for a non-credential purpose (cache key, ETag, checksum) |
| Missing `Secure` on a cookie | Set by the reverse proxy, or the app is HTTPS-only via HSTS preload — verify, don't assume |
| Long session lifetime | Paired with idle timeout and server-side revocation |
