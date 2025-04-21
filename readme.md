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

### Production
Use a real SMTP service like MailKit to send actual emails. Here’s a starting point:

- MailKit NuGet: https://www.nuget.org/packages/MailKit
- Example usage guide: https://github.com/jstedfast/MailKit/blob/master/FAQ.md#sending-messages
- SMTP via Cloudflare guide: [Use Your Domain's Email via SMTP](https://developers.cloudflare.com/email-routing/email-workers/send-email/#sending-email-using-workers-and-smtp)

You can also configure third-party providers such as:
- [SendGrid SMTP Docs](https://docs.sendgrid.com/for-developers/sending-email/smtp-api)
- [Mailgun SMTP Docs](https://documentation.mailgun.com/en/latest/user_manual.html#sending-via-smtp)


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