using System.Security.Claims;
using System.Text;
using CodeWorks.Auth.Interfaces;
using CodeWorks.Auth.Models;
using CodeWorks.Auth.Security;
using CodeWorks.Auth.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;

namespace CodeWorks.Auth.Extensions;

public static class ServiceCollectionExtensions
{
  public static IServiceCollection AddAuthModule<TAccountIdentity, TAccountIdentityStore>(
    this IServiceCollection services,
    Action<JwtOptions> configureJwtOptions,
    IEnumerable<string>? permissionPolicies = null,
    Action<PasskeyOptions>? configurePasskeyOptions = null,
    Action<AuthStoreOptions>? configureStoreOptions = null
)
    where TAccountIdentity : class, IAccountIdentityBase
    where TAccountIdentityStore : class, IAccountIdentityStore<TAccountIdentity>
  {
    // --- Configure options ---
    var jwtOptions = new JwtOptions();
    configureJwtOptions(jwtOptions);

    if (string.IsNullOrWhiteSpace(jwtOptions.SigningKey) || jwtOptions.SigningKey.Length < 32)
      throw new InvalidOperationException("JwtOptions.SigningKey must be at least 32 characters.");
    if (string.IsNullOrWhiteSpace(jwtOptions.Issuer))
      throw new InvalidOperationException("JwtOptions.Issuer is required.");
    if (string.IsNullOrWhiteSpace(jwtOptions.Audience))
      throw new InvalidOperationException("JwtOptions.Audience is required.");

    services.AddSingleton(jwtOptions);
    ClaimsExtensions.Configure(jwtOptions.ClaimMap);

    var passkeyOptions = new PasskeyOptions();
    configurePasskeyOptions?.Invoke(passkeyOptions);
    services.AddSingleton(passkeyOptions);

    var storeOptions = new AuthStoreOptions();
    configureStoreOptions?.Invoke(storeOptions);
    services.AddSingleton(storeOptions);

    // --- Register JwtService with options.ClaimMap ---
    services.AddSingleton<IJwtService>(sp =>
        new JwtService(jwtOptions, jwtOptions.ClaimMap));

    // --- Register stores & auth services ---
    services.AddScoped<IAccountIdentityStore<TAccountIdentity>, TAccountIdentityStore>();
    services.AddScoped<IAuthService<TAccountIdentity>, AuthService<TAccountIdentity>>();
    services.AddSingleton<InMemoryRefreshTokenStore>();
    services.AddSingleton<IRefreshTokenStore>(sp => sp.GetRequiredService<InMemoryRefreshTokenStore>());
    services.AddScoped<IRefreshTokenService<TAccountIdentity>, RefreshTokenService<TAccountIdentity>>();
    services.AddSingleton<IUserMfaStore, InMemoryUserMfaStore>();
    services.AddScoped<IMfaService<TAccountIdentity>, MfaService<TAccountIdentity>>();
    services.AddSingleton<InMemoryPasskeyChallengeStore>();
    services.AddSingleton<IPasskeyChallengeStore>(sp => sp.GetRequiredService<InMemoryPasskeyChallengeStore>());
    services.AddSingleton<IPasskeyCredentialStore, InMemoryPasskeyCredentialStore>();
    services.AddSingleton<IPasskeyResponseVerifier, NoOpPasskeyResponseVerifier>();
    services.AddScoped<IPasskeyService<TAccountIdentity>, PasskeyService<TAccountIdentity>>();
    services.AddSingleton<IAuthAbuseProtector, NoOpAuthAbuseProtector>();
    services.AddSingleton<IAuthorizationHandler, PermissionHandler>();
    services.AddHostedService<AuthStoreCleanupService>();

    // --- Authentication & authorization (same as before) ---
    services.AddAuthentication("Bearer")
        .AddJwtBearer("Bearer", options =>
        {
          options.Events = new JwtBearerEvents
          {
            OnMessageReceived = context =>
            {
              var authHeader = context.Request.Headers.Authorization.FirstOrDefault();
              if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Bearer "))
                context.Token = authHeader["Bearer ".Length..].Trim();

              if (string.IsNullOrEmpty(context.Token) &&
                      context.Request.Cookies.TryGetValue(jwtOptions.CookieName, out var cookieToken))
                context.Token = cookieToken;

              return Task.CompletedTask;
            },
            OnAuthenticationFailed = context =>
            {
              var logger = context.HttpContext.RequestServices
                  .GetService<ILoggerFactory>()
                  ?.CreateLogger("CodeWorks.Auth.Jwt");
              logger?.LogWarning(context.Exception, "JWT authentication failed");
              return Task.CompletedTask;
            },
            OnTokenValidated = context =>
            {
              // Use claim map for dynamic NameClaimType / RoleClaimType
              var identity = new ClaimsIdentity(
                      context.Principal!.Claims,
                      "jwt",
                      jwtOptions.ClaimMap.TryGetValue("Email", out var nameClaim) ? nameClaim : "email",
                      jwtOptions.ClaimMap.TryGetValue("Roles", out var roleClaim) ? roleClaim : ClaimTypes.Role
                  );
              context.Principal = new ClaimsPrincipal(identity);
              return Task.CompletedTask;
            }
          };

          options.TokenValidationParameters = new TokenValidationParameters
          {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtOptions.Issuer,
            ValidAudience = jwtOptions.Audience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptions.SigningKey)),
            ClockSkew = TimeSpan.FromMinutes(5),
            RoleClaimType = ClaimTypes.Role,
            NameClaimType = ClaimTypes.Email
          };
        });

    // --- Permission policies ---
    services.AddAuthorization(options =>
    {
      if (permissionPolicies != null)
      {
        foreach (var permission in permissionPolicies)
          options.AddPolicy(permission, policy =>
              policy.Requirements.Add(new PermissionRequirement(permission)));
      }
    });

    return services;
  }

  public static IServiceCollection AddAuthDistributedStores(this IServiceCollection services)
  {
    services.AddSingleton<DistributedCacheRefreshTokenStore>();
    services.AddSingleton<IRefreshTokenStore>(sp => sp.GetRequiredService<DistributedCacheRefreshTokenStore>());

    services.AddSingleton<DistributedCachePasskeyChallengeStore>();
    services.AddSingleton<IPasskeyChallengeStore>(sp => sp.GetRequiredService<DistributedCachePasskeyChallengeStore>());

    services.AddSingleton<DistributedCachePasskeyCredentialStore>();
    services.AddSingleton<IPasskeyCredentialStore>(sp => sp.GetRequiredService<DistributedCachePasskeyCredentialStore>());

    return services;
  }

  public static IServiceCollection AddAuthDatabaseStores(this IServiceCollection services)
  {
    services.AddSingleton<DbRefreshTokenStore>();
    services.AddSingleton<IRefreshTokenStore>(sp => sp.GetRequiredService<DbRefreshTokenStore>());

    services.AddSingleton<DbPasskeyChallengeStore>();
    services.AddSingleton<IPasskeyChallengeStore>(sp => sp.GetRequiredService<DbPasskeyChallengeStore>());

    services.AddSingleton<DbPasskeyCredentialStore>();
    services.AddSingleton<IPasskeyCredentialStore>(sp => sp.GetRequiredService<DbPasskeyCredentialStore>());

    return services;
  }

}
