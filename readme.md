# AuthModule

A highly flexible, pluggable authentication module for .NET APIs that supports:

- JWT bearer token authentication
- Email/password login with secure hashing
- Role and permission-based authorization via `[Authorize]` and `[HasPermission]`
- Email verification workflows
- Magic link login support
- Abstracted storage and email services for full control


## Features

- ✅ **Storage-agnostic**: Bring your own `User`, `UserStore`, `TokenStore`, and `EmailSender`
- ✅ **Secure by default**: Uses ASP.NET Core Identity's password hasher and JWT best practices
- ✅ **Policy-based authorization**: Out of the box support for roles and custom permissions
- ✅ **Plug-and-play email auth**: Verification and magic link flows supported
- ✅ **Ready for NuGet packaging**

## Release Notes

### v0.1.0

- Security hardening: strict JWT refresh validation, one-time OAuth state consumption, hashed email/magic/reset tokens.
- Session security: refresh token rotation and revocation services with in-memory, distributed-cache, and DB-backed store options.
- MFA and passkeys: TOTP enrollment/verification, recovery codes, passkey challenge/credential services, and pluggable WebAuthn verifier interface.
- Flexible account IDs: support for string, Guid, int, and other notnull ID types via IAccountIdentity<TId>.
- Fast onboarding: SQL Server/PostgreSQL schema scripts, minimal samples, Startup.cs MVC sample, and canonical mvc-sample.http test flow.

## 5-Minute Quickstart

If you want the fastest path, copy one of these files and fill in your store implementations:

- SQL Server sample: `samples/sqlserver/Program.cs`
- PostgreSQL sample: `samples/postgresql/Program.cs`
- Traditional MVC Startup sample: `samples/mvc-startup/`
- SQL Server config template: `samples/sqlserver/appsettings.example.json`
- PostgreSQL config template: `samples/postgresql/appsettings.example.json`

Companion notes are in `samples/README.md`.

## Typed Account IDs

Account IDs are now flexible. You can use `string`, `Guid`, `int`, or any `notnull` type.

- `IAccountIdentityBase` is used internally by the library.
- `IAccountIdentity<TId>` enables typed IDs.
- `IAccountIdentity` remains as a convenience alias for `IAccountIdentity<string>`.

Example with `Guid` IDs:

```csharp
public class AppUser : IAccountIdentity<Guid>
{
    public Guid Id { get; set; }
    public string Email { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Picture { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public bool IsEmailVerified { get; set; }
    public string? Provider { get; set; }
    public string? ProviderId { get; set; }
    public string? ProfilePictureUrl { get; set; }
    public DateTime? LastLoginAt { get; set; }
    public List<string> Roles { get; set; } = [];
    public List<string> Permissions { get; set; } = [];
}
```

## Security Hardening Notes (2026-02)

- JWT refresh now validates signature, issuer, audience, and token algorithm before issuing a new token.
- Direct password reset by email is disabled in `IAuthService<TUser>.ResetPasswordAsync(...)`; use token-based reset via `EmailAuthService`.
- Email verification, magic link, and password reset tokens are now stored as SHA-256 hashes (raw tokens are only sent to users).
- OAuth state validation is one-time use via consume semantics to reduce replay risk.
- Default login abuse hooks are available via `IAuthAbuseProtector` (registered as `NoOpAuthAbuseProtector` by default).

## Session Security: Refresh Token Rotation

The module now supports access + refresh token sessions with one-time refresh token rotation.

```csharp
var session = await authService.LoginWithSessionAsync(email, password);
if (!session.IsSuccessful) return Unauthorized();

// later
var rotated = await authService.RotateRefreshTokenAsync(session.RefreshToken!);
```

`JwtOptions` now includes:

```csharp
options.RefreshTokenExpiration = TimeSpan.FromDays(14);
```

By default, refresh tokens are stored hashed and kept in an in-memory store (`IRefreshTokenStore`).
Replace with your own persistent store for production.

### Distributed stores (Redis / IDistributedCache)

For multi-instance deployments, switch auth stores to distributed cache-backed implementations:

```csharp
services.AddStackExchangeRedisCache(options =>
{
    options.Configuration = Configuration["Redis:ConnectionString"];
});

services.AddAuthModule<AppUser, AppUserStore>(
    options =>
    {
        options.SigningKey = Configuration["Jwt:Key"]!;
        options.Issuer = "your-api";
        options.Audience = "your-users";
    },
    configureStoreOptions: store =>
    {
        store.CleanupInterval = TimeSpan.FromMinutes(5);
        store.RevokedTokenRetention = TimeSpan.FromHours(12);
    });

services.AddAuthDistributedStores();
```

### Database stores (transactional consume semantics)

For strict cross-node consistency, switch to SQL-backed stores.

#### Fast setup (dead simple)

1) Run one script:

- SQL Server: `sql/sqlserver-auth-stores.sql`
- PostgreSQL: `sql/postgresql-auth-stores.sql`

2) Register stores with one call:

```csharp
services.AddAuthDatabaseStores(async ct =>
{
    var connection = new SqlConnection(Configuration.GetConnectionString("AuthDb"));
    await connection.OpenAsync(ct);
    return connection;
});
```

3) Done. Refresh/passkey stores now use transactional DB-backed implementations.

You can also copy the complete ready-to-edit startup files:

- `samples/sqlserver/Program.cs`
- `samples/postgresql/Program.cs`

You can still use explicit factory registration if preferred:

```csharp
services.AddSingleton<IAuthDbConnectionFactory, MyAuthDbConnectionFactory>();
services.AddAuthDatabaseStores();
```

`IAuthDbConnectionFactory` should return an opened `DbConnection` for your provider.

Example:

```csharp
public class MyAuthDbConnectionFactory : IAuthDbConnectionFactory
{
        private readonly string _connectionString;
        public MyAuthDbConnectionFactory(IConfiguration config)
        {
                _connectionString = config["ConnectionStrings:AuthDb"]!;
        }

        public async Task<DbConnection> OpenConnectionAsync(CancellationToken cancellationToken = default)
        {
                var connection = new SqlConnection(_connectionString);
                await connection.OpenAsync(cancellationToken);
                return connection;
        }
}
```

Provider package examples:

```bash
dotnet add package Microsoft.Data.SqlClient
# or
dotnet add package Npgsql
```

PostgreSQL quick factory:

```csharp
services.AddAuthDatabaseStores(async ct =>
{
    var connection = new NpgsqlConnection(Configuration.GetConnectionString("AuthDb"));
    await connection.OpenAsync(ct);
    return connection;
});
```

Required tables:

```sql
CREATE TABLE auth_refresh_tokens (
    token_hash NVARCHAR(200) PRIMARY KEY,
    user_id NVARCHAR(200) NOT NULL,
    created_at DATETIME2 NOT NULL,
    expires_at DATETIME2 NOT NULL,
    revoked_at DATETIME2 NULL,
    replaced_by_token_hash NVARCHAR(200) NULL
);

CREATE TABLE auth_passkey_challenges (
    challenge NVARCHAR(200) PRIMARY KEY,
    user_id NVARCHAR(200) NULL,
    purpose INT NOT NULL,
    created_at DATETIME2 NOT NULL,
    expires_at DATETIME2 NOT NULL
);

CREATE TABLE auth_passkey_credentials (
    credential_id NVARCHAR(256) PRIMARY KEY,
    user_id NVARCHAR(200) NOT NULL,
    public_key NVARCHAR(MAX) NOT NULL,
    sign_count BIGINT NOT NULL,
    created_at DATETIME2 NOT NULL,
    last_used_at DATETIME2 NULL
);

CREATE INDEX ix_auth_passkey_credentials_user_id ON auth_passkey_credentials (user_id);
CREATE INDEX ix_auth_refresh_tokens_user_id ON auth_refresh_tokens (user_id);
CREATE INDEX ix_auth_refresh_tokens_expires_at ON auth_refresh_tokens (expires_at);
CREATE INDEX ix_auth_passkey_challenges_expires_at ON auth_passkey_challenges (expires_at);
```

`AddAuthDistributedStores()` swaps these defaults:

- `IRefreshTokenStore` → `DistributedCacheRefreshTokenStore`
- `IPasskeyChallengeStore` → `DistributedCachePasskeyChallengeStore`
- `IPasskeyCredentialStore` → `DistributedCachePasskeyCredentialStore`

The built-in cleanup hosted service (`AuthStoreCleanupService`) runs automatically for in-memory stores and is a no-op for distributed cache entries that already expire in cache.

## MFA: Authenticator Apps + Recovery Codes

The module includes built-in TOTP primitives for authenticator apps:

```csharp
var enrollment = await mfaService.BeginAuthenticatorEnrollmentAsync(user, "CodeWorks");
// Show enrollment.AuthenticatorUri as QR code or manual entry key

var enabled = await mfaService.EnableAuthenticatorAsync(user, codeFromApp);
var recoveryCodes = await mfaService.GenerateRecoveryCodesAsync(user);
```

Validation:

```csharp
var validTotp = await mfaService.VerifyAuthenticatorCodeAsync(user, code);
var usedRecoveryCode = await mfaService.RedeemRecoveryCodeAsync(user, recoveryCode);
```

## Device Keychains / Passkeys

The module now includes a concrete `PasskeyService<TUser>` with:

- challenge generation and expiry checks,
- one-time challenge consumption,
- credential metadata persistence via `IPasskeyCredentialStore`,
- auth challenge persistence via `IPasskeyChallengeStore`.

### Required verifier for production WebAuthn

`PasskeyService<TUser>` delegates cryptographic attestation/assertion checks to `IPasskeyResponseVerifier`.
By default, `NoOpPasskeyResponseVerifier` is registered (fails closed), so register your verifier implementation:

```csharp
services.AddSingleton<IPasskeyResponseVerifier, MyWebAuthnResponseVerifier>();
services.AddSingleton<IPasskeyCredentialStore, MyPasskeyCredentialStore>();
services.AddSingleton<IPasskeyChallengeStore, MyPasskeyChallengeStore>();
```

### Passkey options

Configure RP metadata and origin during module registration:

```csharp
services.AddAuthModule<AppUser, AppUserStore>(
    options =>
    {
        options.SigningKey = Configuration["Jwt:Key"]!;
        options.Issuer = "your-api";
        options.Audience = "your-users";
    },
    permissionPolicies: new[] { "CanViewReports" },
    configurePasskeyOptions: passkey =>
    {
        passkey.RpId = "app.example.com";
        passkey.RpName = "Example App";
        passkey.ExpectedOrigin = "https://app.example.com";
        passkey.ChallengeLifetime = TimeSpan.FromMinutes(5);
    });
```

### Replay/race hardening behavior

- Refresh token rotation uses consume-then-rotate semantics (`TryConsumeActiveTokenAsync`) to reduce replay windows.
- Passkey challenges are consumed once and removed during verification (`ConsumeAsync`), preventing challenge reuse.
- In distributed mode, atomicity depends on your cache provider capabilities; for strict cross-node transactional guarantees, use database-backed store implementations.

### Optional Login Abuse Protection

Implement `IAuthAbuseProtector` to add lockout and throttling policies:

```csharp
public class RedisAuthAbuseProtector : IAuthAbuseProtector
{
    public Task<bool> IsLoginAllowedAsync(string email) => Task.FromResult(true);
    public Task RecordFailedLoginAsync(string email) => Task.CompletedTask;
    public Task RecordSuccessfulLoginAsync(string email) => Task.CompletedTask;
}

services.AddSingleton<IAuthAbuseProtector, RedisAuthAbuseProtector>();
```


## Installation

Add the package (once published):

```bash
Install-Package CodeWorks.Auth
```


## Getting Started

### 1. Define Your User

```csharp
public class AppUser : IUser
{
    public string Id { get; set; }
    public string Email { get; set; }
    public string PasswordHash { get; set; }
    public bool IsEmailVerified { get; set; }
    public IEnumerable<string> Roles { get; set; }
    public IEnumerable<string> Permissions { get; set; }
}
```

### 2. Implement Required Interfaces

#### `IUserStore<TUser>`
Manages user persistence (load/save/verify).

#### `IUserTokenStore`
Manages tokens used for email verification or magic login.

#### `IUserEmailSender`
Sends emails to users with custom logic (SMTP, SendGrid, etc.).


### 3. Register the Module

```csharp
services.AddAuthModule<AppUser, AppUserStore>(options =>
{
    options.SigningKey = Configuration["Jwt:Key"];
    options.Issuer = "your-api";
    options.Audience = "your-users";
    options.Expiration = TimeSpan.FromHours(1);
},
new[] { "CanViewReports", "CanDeleteUsers" });

Services.AddOAuthProviders(builder.Configuration);
Services.AddScoped<IOAuthService<AppUser>, OAuthService<AppUser>>();
```


## Usage

### Login and Registration
Use `IAuthService<TUser>`:

```csharp
await authService.RegisterAsync(user, password);
await authService.LoginAsync(email, password);
```

### Email Verification & Magic Links
Use `EmailAuthService<TUser>`:

```csharp
await emailAuth.RequestVerificationEmailAsync(user, "https://your.site/verify");
await emailAuth.ConfirmEmailAsync(token);

await emailAuth.RequestMagicLinkAsync(email, "https://your.site/login");
await emailAuth.RedeemMagicLinkAsync(token);
```


## Authorization

### Roles
```csharp
[Authorize(Roles = "Admin")]
```

### Permissions
```csharp
[HasPermission("CanDeleteUsers")]
```


## Email Setup

### Development
For local development, use a simple log-based sender:

```csharp
public class DevEmailSender : IUserEmailSender
{
    private readonly ILogger<DevEmailSender> _logger;

    public DevEmailSender(ILogger<DevEmailSender> logger)
    {
        _logger = logger;
    }

    public Task SendVerificationEmailAsync(IUser user, string tokenUrl)
    {
        _logger.LogInformation($"[DEV] Verification link for {user.Email}: {tokenUrl}");
        return Task.CompletedTask;
    }

    public Task SendMagicLinkAsync(IUser user, string tokenUrl)
    {
        _logger.LogInformation($"[DEV] Magic login link for {user.Email}: {tokenUrl}");
        return Task.CompletedTask;
    }
}
```

Register it conditionally:
```csharp
if (env.IsDevelopment())
{
    services.AddScoped<IUserEmailSender, DevEmailSender>();
}
```


### AuthController Example

```csharp
[ApiController]
[Route("api/auth")]
public class OAuthController<TUser> : ControllerBase 
    where TUser : IOAuthUser, new()
{
    private readonly IOAuthService<TUser> _oauthService;
    private readonly SignInManager<TUser> _signInManager;

    public OAuthController(
        IOAuthService<TUser> oauthService,
        SignInManager<TUser> signInManager)
    {
        _oauthService = oauthService;
        _signInManager = signInManager;
    }

    [HttpGet("google")]
    public IActionResult GoogleLogin(string returnUrl = "/")
    {
        var redirectUrl = Url.Action(
            nameof(GoogleCallback), 
            new { returnUrl });
        
        var properties = _signInManager.ConfigureExternalAuthenticationProperties(
            "Google", 
            redirectUrl);
        
        return Challenge(properties, "Google");
    }

    [HttpGet("google/callback")]
    public async Task<IActionResult> GoogleCallback(string returnUrl = "/")
    {
        var info = await _signInManager.GetExternalLoginInfoAsync();
        if (info == null)
        {
            return BadRequest(new { error = "Error loading external login info" });
        }

        var result = await _oauthService.HandleOAuthCallbackAsync(info);
        
        if (!result.Success)
        {
            return BadRequest(new { error = result.ErrorMessage });
        }

        // Return token to client
        return Ok(new
        {
            token = result.Token,
            user = new
            {
                result.User.Id,
                result.User.Email,
                result.User.Roles,
                result.User.ProfilePictureUrl
            }
        });
    }

    [HttpGet("facebook")]
    public IActionResult FacebookLogin(string returnUrl = "/")
    {
        var redirectUrl = Url.Action(
            nameof(FacebookCallback), 
            new { returnUrl });
        
        var properties = _signInManager.ConfigureExternalAuthenticationProperties(
            "Facebook", 
            redirectUrl);
        
        return Challenge(properties, "Facebook");
    }

    [HttpGet("facebook/callback")]
    public async Task<IActionResult> FacebookCallback(string returnUrl = "/")
    {
        var info = await _signInManager.GetExternalLoginInfoAsync();
        if (info == null)
        {
            return BadRequest(new { error = "Error loading external login info" });
        }

        var result = await _oauthService.HandleOAuthCallbackAsync(info);
        
        if (!result.Success)
        {
            return BadRequest(new { error = result.ErrorMessage });
        }

        return Ok(new
        {
            token = result.Token,
            user = new
            {
                result.User.Id,
                result.User.Email,
                result.User.Roles,
                result.User.ProfilePictureUrl
            }
        });
    }
}
```

### OAuth State Store

You will want some implementation of State Store for OAuth callbacks. There are two services based on need you can use an InMemory or DistributedCache. Both implement the same `IOAuthStateStore` as in the example below if you prefer something more like using your own DB. 



```csharp
/// <summary>
/// Database implementation for OAuth state store
/// Best for persistence and audit trail requirements
/// </summary>
public class DatabaseOAuthStateStore : IOAuthStateStore
{
    private readonly IDbConnection _db;
    private readonly ILogger<DatabaseOAuthStateStore> _logger;

    public DatabaseOAuthStateStore(
        IDbConnection db,
        ILogger<DatabaseOAuthStateStore> logger)
    {
        _db = db;
        _logger = logger;
    }

    public async Task StoreStateAsync(OAuthState state)
    {
        const string sql = @"
            INSERT INTO oauth_states (token, provider, return_url, created_at, expires_at, is_used)
            VALUES (@Token, @Provider, @ReturnUrl, @CreatedAt, @ExpiresAt, @IsUsed)";

        await _db.ExecuteAsync(sql, state);
        _logger.LogDebug("Stored OAuth state in database: {Token}", state.Token);
    }

    public async Task<OAuthState?> GetStateAsync(string token)
    {
        const string sql = @"
            SELECT token, provider, return_url as ReturnUrl, created_at as CreatedAt, 
                   expires_at as ExpiresAt, is_used as IsUsed
            FROM oauth_states 
            WHERE token = @token";

        return await _db.QueryFirstOrDefaultAsync<OAuthState>(sql, new { token });
    }

    public async Task UpdateStateAsync(OAuthState state)
    {
        const string sql = @"
            UPDATE oauth_states 
            SET is_used = @IsUsed, return_url = @ReturnUrl
            WHERE token = @Token";

        await _db.ExecuteAsync(sql, state);
        _logger.LogDebug("Updated OAuth state in database: {Token}", state.Token);
    }

    public async Task DeleteStateAsync(string token)
    {
        const string sql = "DELETE FROM oauth_states WHERE token = @token";
        await _db.ExecuteAsync(sql, new { token });
        _logger.LogDebug("Deleted OAuth state from database: {Token}", token);
    }

    public async Task CleanupExpiredStatesAsync()
    {
        const string sql = "DELETE FROM oauth_states WHERE expires_at < @now";
        var deletedCount = await _db.ExecuteAsync(sql, new { now = DateTime.UtcNow });

        if (deletedCount > 0)
        {
            _logger.LogInformation("Cleaned up {Count} expired OAuth states from database", deletedCount);
        }
    }
}
```


### Production
Use a real SMTP service like MailKit to send actual emails. Here’s a starting point:

- MailKit NuGet: https://www.nuget.org/packages/MailKit
- Example usage guide: https://github.com/jstedfast/MailKit/blob/master/FAQ.md#sending-messages
- SMTP via Cloudflare guide: [Use Your Domain's Email via SMTP](https://developers.cloudflare.com/email-routing/email-workers/send-email/#sending-email-using-workers-and-smtp)

You can also configure third-party providers such as:
- [SendGrid SMTP Docs](https://docs.sendgrid.com/for-developers/sending-email/smtp-api)
- [Mailgun SMTP Docs](https://documentation.mailgun.com/en/latest/user_manual.html#sending-via-smtp)



### OAuth Provider Setup

- Google OAuth:
    - Go to [Google Cloud Console](https://console.cloud.google.com/)
    - Create OAuth 2.0 credentials
    - Add authorized redirect URI: https://yourdomain.com/api/auth/google/callback

- Facebook OAuth:
    - Go to [Facebook Developers](https://developers.facebook.com/)
    - Create a new app
    - Add Facebook Login product
    - Add redirect URI: https://yourdomain.com/api/auth/facebook/callback


1. Install Required NuGet Packages:
```bash
dotnet add package Microsoft.AspNetCore.Authentication.Google
dotnet add package Microsoft.AspNetCore.Authentication.Facebook
```

2. Add OAuth Configuration to appsettings.json
```json
{
  "Authentication": {
    "Google": {
      "ClientId": "your-google-client-id",
      "ClientSecret": "your-google-client-secret"
    },
    "Facebook": {
      "AppId": "your-facebook-app-id",
      "AppSecret": "your-facebook-app-secret"
    }
  },
  "Jwt": {
    "Key": "your-signing-key",
    "Issuer": "your-api",
    "Audience": "your-users"
  }
}
```


## Extensibility

- `IUser` - your user model
- `IUserStore<TUser>` - storage logic
- `IUserTokenStore` - token persistence
- `IUserEmailSender` - email transport


## Roadmap

- [ ] Multi-factor authentication
- [ ] TOTP support

## License

MIT or commercial dual-license (TBD).