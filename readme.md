# AuthModule

A highly flexible, pluggable authentication module for .NET APIs that supports:

- JWT bearer token authentication
- Email/password login with secure hashing
- Role and permission-based authorization via `[Authorize]` and `[HasPermission]`
- Email verification workflows
- Magic link login support
- Abstracted storage and email services for full control

---

## Features

- ✅ **Storage-agnostic**: Bring your own `User`, `UserStore`, `TokenStore`, and `EmailSender`
- ✅ **Secure by default**: Uses ASP.NET Core Identity's password hasher and JWT best practices
- ✅ **Policy-based authorization**: Out of the box support for roles and custom permissions
- ✅ **Plug-and-play email auth**: Verification and magic link flows supported
- ✅ **Ready for NuGet packaging**

---

## Installation

Add the package (once published):

```bash
Install-Package AuthModule
```

---

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

---

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

---

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

---

## Authorization

### Roles
```csharp
[Authorize(Roles = "Admin")]
```

### Permissions
```csharp
[HasPermission("CanDeleteUsers")]
```

---

## Extensibility

- `IUser` - your user model
- `IUserStore<TUser>` - storage logic
- `IUserTokenStore` - token persistence
- `IUserEmailSender` - email transport

---

## Roadmap

- [ ] Multi-factor authentication
- [ ] Password reset tokens
- [ ] TOTP support
- [ ] NuGet packaging & GitHub Actions

---

## License

MIT or commercial dual-license (TBD).

---

Happy authenticating ✨

