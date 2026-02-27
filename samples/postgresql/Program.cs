using System.Data.Common;
using CodeWorks.Auth.Extensions;
using CodeWorks.Auth.Interfaces;
using CodeWorks.Auth.Models;
using Npgsql;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthModule<AppUser, AppUserStore>(
  options =>
  {
    options.SigningKey = builder.Configuration["Jwt:Key"]!;
    options.Issuer = "your-api";
    options.Audience = "your-users";
    options.Expiration = TimeSpan.FromHours(1);
    options.RefreshTokenExpiration = TimeSpan.FromDays(14);
  },
  configureStoreOptions: store =>
  {
    store.CleanupInterval = TimeSpan.FromMinutes(5);
    store.RevokedTokenRetention = TimeSpan.FromHours(12);
  });

builder.Services.AddAuthDatabaseStores(async ct =>
{
  DbConnection connection = new NpgsqlConnection(builder.Configuration.GetConnectionString("AuthDb"));
  await connection.OpenAsync(ct);
  return connection;
});

builder.Services.AddSingleton<IPasskeyResponseVerifier, MyWebAuthnResponseVerifier>();
builder.Services.AddScoped<IUserTokenStore, MyUserTokenStore>();
builder.Services.AddScoped<IUserEmailSender, MyUserEmailSender>();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/health", () => Results.Ok(new { ok = true }));

app.Run();

public class AppUser : IAccountIdentity<int>
{
  public int Id { get; set; }
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

public class AppUserStore : IAccountIdentityStore<AppUser>
{
  public Task<AppUser> FindByEmailAsync(string email) => throw new NotImplementedException();
  public Task<bool> EmailExistsAsync(string email) => throw new NotImplementedException();
  public Task<AppUser> UpdateAsync(AppUser user) => throw new NotImplementedException();
  public Task<AppUser> FindByIdAsync(string id) => throw new NotImplementedException();
  public Task<AppUser> FindByProviderAsync(string provider, string providerId) => throw new NotImplementedException();
  public Task<AppUser> CreateAsync(AppUser user) => throw new NotImplementedException();
  public Task DeleteAsync(string id) => throw new NotImplementedException();
}

public class MyWebAuthnResponseVerifier : IPasskeyResponseVerifier
{
  public Task<PasskeyRegistrationValidationResult> VerifyRegistrationAsync(string attestationResponseJson, string expectedChallenge, string expectedUserId, PasskeyOptions options)
    => Task.FromResult(PasskeyRegistrationValidationResult.Failure());

  public Task<PasskeyAuthenticationValidationResult> VerifyAuthenticationAsync(string assertionResponseJson, string expectedChallenge, PasskeyCredentialRecord credential, PasskeyOptions options)
    => Task.FromResult(PasskeyAuthenticationValidationResult.Failure());
}

public class MyUserTokenStore : IUserTokenStore
{
  public Task SaveTokenAsync(TokenRecord token) => throw new NotImplementedException();
  public Task<TokenRecord> GetValidTokenAsync(string token, EmailTokenPurpose purpose) => throw new NotImplementedException();
  public Task MarkTokenUsedAsync(string token) => throw new NotImplementedException();
}

public class MyUserEmailSender : IUserEmailSender
{
  public Task SendVerificationEmailAsync(IAccountIdentityBase user, string tokenUrl) => Task.CompletedTask;
  public Task SendMagicLinkAsync(IAccountIdentityBase user, string tokenUrl) => Task.CompletedTask;
  public Task SendPasswordResetEmailAsync(IAccountIdentityBase user, string tokenUrl) => Task.CompletedTask;
}
