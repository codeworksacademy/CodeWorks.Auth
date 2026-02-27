# MVC Startup sample

Traditional ASP.NET Core Web API setup using `Startup.cs`.

## Includes
- `AuthController` with register/login/refresh endpoints
- `[Authorize]` `AccountController` with protected `GET /api/account/me`
- In-memory sample user/token stores to run quickly

## Run
1. Copy `appsettings.example.json` to `appsettings.json`
2. Set `Jwt:Key` to a long random secret (32+ chars)
3. Run:

```bash
dotnet run --project samples/mvc-startup/CodeWorks.Auth.MvcSample.csproj
```

## Try it
1. `POST /api/auth/register`
2. Use `accessToken` in `Authorization: Bearer <token>`
3. Call `GET /api/account/me`

## HTTP file (recommended)
- Open `mvc-sample.http` in VS Code
- Run in order: `Bootstrap Register (200 or 400)` → `Login` → `Refresh` → `Get Me (Authorized)`
- Tokens are captured automatically into variables for the next requests
- This is deterministic for repeated runs (user exists or not)

## Postman (optional)
- `CodeWorks.Auth.MvcSample.postman_collection.json`
- `CodeWorks.Auth.MvcSample.postman_environment.json`
