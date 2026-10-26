## Interview cheat sheet

**Authentication vs. authorization:** authentication answers "who are you?" (login gives a token, and failing it is a 401). Authorization answers "what can you do?" (roles, and failing it is a 403).

**JWT structure:** `header.payload.signature`, Base64URL-encoded. The payload is *not encrypted*: anyone can read it, so never put passwords or secrets in it. The signature, an HMAC with a secret only the server knows, proves nobody tampered with the token.

**Why JWT/stateless:** the server stores no session, so it scales horizontally (any server can validate the token), and it suits REST, microservices and mobile apps.

**The JWT downside:** you can't easily revoke a token before it expires. The fixes are short access-token expiry (15 minutes) with refresh tokens, a token blacklist (for example in Redis) on logout, or a `tokenVersion` stored on the user.

**Why CSRF is disabled:** CSRF attacks rely on the browser auto-sending cookies. Our token travels in the `Authorization` header, which the browser never adds automatically. If you move the JWT into a cookie, you must turn CSRF protection back on.

**Why BCrypt:** it's a one-way hash with a random salt (identical passwords get different hashes) and is deliberately slow, which resists brute force. Never encrypt passwords (encryption is reversible), and never use MD5 or SHA-1.

**`SessionCreationPolicy.STATELESS`:** no HttpSession and no JSESSIONID, so every request must carry the JWT.

**`OncePerRequestFilter`:** guarantees the filter runs only once per request (even on forwards or includes).

**`hasRole("ADMIN")` vs `hasAuthority("ROLE_ADMIN")`:** these are the same check. `hasRole` adds the `ROLE_` prefix for you.

**`@EnableMethodSecurity`:** enables `@PreAuthorize` on methods. In Spring Security 6 it replaced `@EnableGlobalMethodSecurity`.

**What changed in Spring Security 6:** `WebSecurityConfigurerAdapter` was removed, so you now expose a `SecurityFilterChain` bean. `antMatchers` became `requestMatchers`, and configuration uses lambda DSL.

**Where to keep the secret:** in an environment variable or a vault (`${JWT_SECRET}`), never in Git. HS256 needs a key of at least 256 bits (32 bytes).

**HS256 vs. RS256:** HS256 uses one shared secret for both signing and verifying. RS256 signs with a private key and verifies with a public key, which is better when many services only need to *verify* tokens (OAuth2, microservices).

**Same error for a wrong email and a wrong password:** returning one message stops attackers from finding out which emails are registered (user enumeration).

**Role from the client on register?** Never accept it. That's a privilege-escalation hole, so the server always assigns USER.

**Possible improvements to mention:** refresh-token rotation and storing refresh tokens in the DB, logout via a blacklist, account lockout or rate limiting on login, email verification, HTTPS everywhere, and OAuth2/Google login.

## Practice plan

1. Read every file once, in the order above. The comments explain the *why*.
2. Delete the `security/` and `config/` folders and rewrite them from memory.
3. Next, start from an empty Spring Initializr project and build it all within 60 minutes.
4. Explain the two flow diagrams out loud, as if the interviewer were watching.
