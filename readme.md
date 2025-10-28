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