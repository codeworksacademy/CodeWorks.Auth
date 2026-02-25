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
using Microsoft.IdentityModel.Tokens;

namespace CodeWorks.Auth.Extensions;

public static class ServiceCollectionExtensions
{
  public static IServiceCollection AddAuthModule<TAccountIdentity, TAccountIdentityStore>(
    this IServiceCollection services,
    Action<JwtOptions> configureJwtOptions,
    IEnumerable<string>? permissionPolicies = null,
    Action<PasskeyOptions>? configurePasskeyOptions = null
)
    where TAccountIdentity : class, IAccountIdentity
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

    // --- Register JwtService with options.ClaimMap ---
    services.AddSingleton<IJwtService>(sp =>
        new JwtService(jwtOptions, jwtOptions.ClaimMap));

    // --- Register stores & auth services ---
    services.AddScoped<IAccountIdentityStore<TAccountIdentity>, TAccountIdentityStore>();
    services.AddScoped<IAuthService<TAccountIdentity>, AuthService<TAccountIdentity>>();
    services.AddSingleton<IRefreshTokenStore, InMemoryRefreshTokenStore>();
    services.AddScoped<IRefreshTokenService<TAccountIdentity>, RefreshTokenService<TAccountIdentity>>();
    services.AddSingleton<IUserMfaStore, InMemoryUserMfaStore>();
    services.AddScoped<IMfaService<TAccountIdentity>, MfaService<TAccountIdentity>>();
    services.AddSingleton<IPasskeyChallengeStore, InMemoryPasskeyChallengeStore>();
    services.AddSingleton<IPasskeyCredentialStore, InMemoryPasskeyCredentialStore>();
    services.AddSingleton<IPasskeyResponseVerifier, NoOpPasskeyResponseVerifier>();
    services.AddScoped<IPasskeyService<TAccountIdentity>, PasskeyService<TAccountIdentity>>();
    services.AddSingleton<IAuthAbuseProtector, NoOpAuthAbuseProtector>();
    services.AddSingleton<IAuthorizationHandler, PermissionHandler>();

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

}
