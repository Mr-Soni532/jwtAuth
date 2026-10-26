# JWT Auth Demo — Spring Boot 3 + Spring Security 6

A complete login + JWT flow for interview practice. It covers register, login, protected APIs, role-based access (USER/ADMIN), refresh tokens, and clean 401/403 errors.

**Stack:** Java 17+, Spring Boot 3.3, Spring Security 6, JPA, H2 (in-memory; swap to MySQL in `pom.xml` and `application.properties`), JJWT 0.12.

## Run

```bash
mvn spring-boot:run      # starts on http://localhost:8080
mvn test                 # runs AuthFlowTest (the whole flow end to end)
```

Default admin (seeded on startup): `admin@demo.com` / `admin123`

## Project structure (build it in this order in the interview)

```
entity/      User, Role                    1. Data model
repository/  UserRepository                2. findByEmail, existsByEmail
dto/         AuthDtos (records)            3. Request/response objects with @Valid rules
security/    JwtService                    4. Generate, parse and validate tokens
             CustomUserDetailsService      5. Load user from DB for Spring Security
             JwtAuthFilter                 6. Read Bearer token on every request
             SecurityErrorHandlers         7. JSON 401 / 403
config/      SecurityConfig                8. Filter chain, stateless, BCrypt, rules
service/     AuthService                   9. register / login / refresh logic
controller/  Auth, User, Admin            10. Endpoints
exception/   GlobalExceptionHandler       11. Consistent error JSON
config/      DataSeeder                   12. Seeds the default admin
```

## APIs

| Method | URL | Access | Purpose |
|---|---|---|---|
| POST | `/api/auth/register` | Public | Create a user (role is always USER) |
| POST | `/api/auth/login` | Public | Returns access + refresh token |
| POST | `/api/auth/refresh` | Public | Refresh token → new access token |
| GET | `/api/user/me` | Any logged-in user | Current user's profile |
| GET | `/api/admin/users` | ADMIN only | List all users |

### Try it with curl

```bash
# Register
curl -X POST localhost:8080/api/auth/register -H "Content-Type: application/json" \
  -d '{"name":"Raj","email":"raj@test.com","password":"secret123"}'

# Login (copy accessToken from the response)
curl -X POST localhost:8080/api/auth/login -H "Content-Type: application/json" \
  -d '{"email":"raj@test.com","password":"secret123"}'

# Protected call
curl localhost:8080/api/user/me -H "Authorization: Bearer <accessToken>"

# Admin call with a USER token -> 403
curl localhost:8080/api/admin/users -H "Authorization: Bearer <accessToken>"

# Refresh
curl -X POST localhost:8080/api/auth/refresh -H "Content-Type: application/json" \
  -d '{"refreshToken":"<refreshToken>"}'
```

Paste any token into https://jwt.io to show the interviewer the header, payload and signature.

## The flow (explain it like this)

**Login**

```
Client --POST /login {email,pwd}--> AuthController -> AuthService
   -> AuthenticationManager.authenticate()
        -> DaoAuthenticationProvider
             -> CustomUserDetailsService.loadUserByUsername(email)   (DB)
             -> BCrypt.matches(rawPwd, storedHash)
   -> wrong? BadCredentialsException -> 401
   -> ok?    JwtService.generateAccessToken + generateRefreshToken
<-- { accessToken, refreshToken, tokenType: "Bearer", expiresInMs, role }
```

**Every protected request**

```
Client --GET /api/user/me + "Authorization: Bearer <jwt>"-->
  JwtAuthFilter (OncePerRequestFilter, runs before UsernamePasswordAuthenticationFilter)
    1. no header?            -> continue as anonymous -> 401 from EntryPoint
    2. parse token           -> checks signature + expiry (invalid/expired -> 401)
    3. load user, check sub matches and type == "access"
    4. SecurityContextHolder.setAuthentication(...)
  Authorization rules: authenticated()? hasRole("ADMIN")? -> else 403
  Controller runs; @AuthenticationPrincipal gives the current user
```

**Token expired:** the frontend calls `/api/auth/refresh` with the refresh token, gets a new access token, and retries the request. The user doesn't log in again until the refresh token expires (7 days).

## Frontend side (React + Axios), for the "full stack" part

```js
// api.js
import axios from "axios";
const api = axios.create({ baseURL: "http://localhost:8080/api" });

// Attach the token to every request
api.interceptors.request.use(cfg => {
  const token = localStorage.getItem("accessToken");
  if (token) cfg.headers.Authorization = `Bearer ${token}`;
  return cfg;
});

// On 401: try a refresh once, then retry; otherwise log out
api.interceptors.response.use(r => r, async err => {
  const original = err.config;
  if (err.response?.status === 401 && !original._retry) {
    original._retry = true;
    try {
      const { data } = await axios.post("http://localhost:8080/api/auth/refresh",
        { refreshToken: localStorage.getItem("refreshToken") });
      localStorage.setItem("accessToken", data.accessToken);
      original.headers.Authorization = `Bearer ${data.accessToken}`;
      return api(original);
    } catch {
      localStorage.clear();
      window.location.href = "/login";
    }
  }
  return Promise.reject(err);
});
export default api;

// Protected route
const PrivateRoute = ({ children }) =>
  localStorage.getItem("accessToken") ? children : <Navigate to="/login" />;
```

> localStorage is simple but readable by JavaScript, so it is exposed if the site has an XSS bug. A safer production choice is the refresh token in an **HttpOnly, Secure, SameSite cookie** and the access token in memory. Mention this trade-off and you'll earn points.

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
