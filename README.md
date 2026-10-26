# JWT Auth Demo — Spring Boot 3 + Spring Security 6

A complete login + JWT flow for  practice. It covers register, login, protected APIs, role-based access (USER/ADMIN), refresh tokens, and clean 401/403 errors.

**Stack:** Java 17+, Spring Boot 3.3, Spring Security 6, JPA, H2 (in-memory; swap to MySQL in `pom.xml` and `application.properties`), JJWT 0.12.

## Run

```bash
mvn spring-boot:run      # starts on http://localhost:8080
mvn test                 # runs AuthFlowTest (the whole flow end to end)
```

Default admin (seeded on startup): `admin@demo.com` / `admin123`

## Project structure (build it in this order in the )

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

Paste any token into https://jwt.io to show the er the header, payload and signature.

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

