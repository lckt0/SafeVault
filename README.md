# SafeVault

SafeVault is a small ASP.NET Core 8 web API (with a minimal web front end) where users register, sign in and keep private notes.
It is the capstone project of the *Security and Authentication* course and combines the three activities:

1. **Secure code generation** – allow-list input validation and parameterized SQL (SQL injection prevention).
2. **Authentication and authorization** – salted password hashing, JWT bearer authentication and role-based access control (RBAC).
3. **Debugging security issues** – finding and fixing SQL injection, XSS and broken access control, then proving the fixes with tests.

## Project layout

```
SafeVault.sln
src/SafeVault/
  Program.cs                  pipeline: JWT auth, authorization policies, rate limiting, security headers
  Security/InputValidator.cs  allow-list validation for usernames, emails, passwords, note fields, roles
  Security/PasswordHasher.cs  PBKDF2-HMAC-SHA512, 210,000 iterations, random 16-byte salt, constant-time compare
  Security/AuthService.cs     registration (always role "user"), login, admin seeding
  Security/TokenService.cs    signed JWTs (HS256) with sub / name / role claims
  Security/Policies.cs        "Authenticated" and "AdminOnly" policies, deny-by-default fallback policy
  Security/SecurityHeaders.cs CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Cache-Control
  Data/*.cs                   SQLite access with parameterized commands only
  Endpoints/*.cs              /api/auth, /api/notes, /api/users/me, /api/admin
  wwwroot/                    index.html + app.js (renders with textContent only)
tests/SafeVault.Tests/        NUnit tests (unit + full HTTP pipeline via WebApplicationFactory)
```

## API

| Method | Route | Access |
|---|---|---|
| POST | `/api/auth/register` | anonymous, rate limited |
| POST | `/api/auth/login` | anonymous, rate limited – returns a JWT |
| GET | `/api/users/me` | user, admin |
| GET / POST | `/api/notes` | user, admin (own notes) |
| GET / DELETE | `/api/notes/{id}` | owner or admin |
| GET | `/api/notes/{id}/preview` | owner or admin – server-rendered, HTML-encoded |
| GET | `/api/admin/dashboard` | admin |
| GET | `/api/admin/users?search=` | admin |
| PUT | `/api/admin/users/{username}/role` | admin |

## Vulnerabilities found and how they were fixed

| # | Vulnerability | Vulnerable pattern | Fix |
|---|---|---|---|
| 1 | SQL injection in user lookup / search | `"SELECT ... WHERE Username = '" + username + "'"` and `LIKE '%" + term + "%'` | Static SQL text with `SqliteParameter` binding (`$username`, `$pattern`); LIKE wildcards `%`, `_`, `\` escaped with `ESCAPE '\'` |
| 2 | Missing input validation | any string accepted for username/email/password | `InputValidator`: allow-list regex + length limits, `MailAddress` check, password policy, title rejects `<`/`>`, control characters rejected, role allow-list |
| 3 | Stored XSS in note view | note title/content concatenated into HTML; front end used `innerHTML` | `HtmlEncoder.Default.Encode` for every value in the HTML preview, strict `JavaScriptEncoder.Default` for JSON (`<` becomes `<`), front end uses `textContent`, CSP `script-src 'self'` |
| 4 | Plain-text / unsalted passwords | password stored and compared as-is | PBKDF2-SHA512 with per-user salt and `CryptographicOperations.FixedTimeEquals`; dummy verification for unknown users so timing does not reveal valid usernames |
| 5 | Broken access control (IDOR) | `GET /api/notes/{id}` returned any note | Ownership check: owner or admin only, others get 404 |
| 6 | Missing role checks / privilege escalation | admin routes only required a login; `role` accepted in the register body | `AdminOnly` policy on the whole `/api/admin` group, registration always assigns `user`, roles changed only by an admin |
| 7 | Weak token handling | unsigned or weakly validated tokens | Issuer, audience, lifetime, signing key and algorithm (`HS256` only) validated; key must be configured and at least 32 bytes |
| 8 | Credential brute forcing / user enumeration | unlimited login attempts, different messages | Fixed-window rate limiter on `/api/auth/*` (429), one generic "Invalid username or password." message |

## Running

Requires the .NET 8 SDK.

```bash
dotnet build
dotnet test
cd src/SafeVault
dotnet run            # Development: http://localhost:5210, ephemeral JWT key
```

Outside Development the app refuses to start without a signing key:

```bash
export Jwt__Key="<random string of at least 32 bytes>"
export Seed__AdminUsername="admin"           # optional bootstrap administrator
export Seed__AdminPassword="<strong password>"
```

## Tests

74 NUnit tests, all passing:

- `TestInputValidation` – valid values accepted; SQL/XSS payloads, bad emails, weak passwords and unknown roles rejected.
- `TestSqlInjection` – `' OR 1=1 --`, `UNION SELECT`, `DROP TABLE` payloads against lookup, search, login and registration; payloads are stored verbatim and the tables stay intact.
- `TestXss` – script tags rejected in usernames/titles, encoded in the HTML preview and JSON, security headers present, front end free of `innerHTML`.
- `TestAuthorization` – login, generic errors, duplicate users, no self-assigned admin, 401 without/with forged or `alg: none` tokens, 403 for users on admin routes, admin promotion, note ownership (IDOR).
- `TestPasswordHashing` – salted hashes, correct/incorrect verification, malformed hashes.
- `TestRateLimiting` – the fourth login attempt inside the window returns 429.
