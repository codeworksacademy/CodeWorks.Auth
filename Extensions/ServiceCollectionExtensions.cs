using System.Security.Claims;
using System.Text;
using CodeWorks.Auth.Interfaces;
using CodeWorks.Auth.Security;
using CodeWorks.Auth.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace CodeWorks.Auth.Extensions;

public static class ServiceCollectionExtensions
{
  public static IServiceCollection AddAuthModule<TAccountIdentity, TAccountIdentityStore>(
      this IServiceCollection services,
      Action<JwtOptions> configureJwtOptions,
      IEnumerable<string>? permissionPolicies = null
  )
      where TAccountIdentity : class, IAccountIdentity
      where TAccountIdentityStore : class, IAccountIdentityStore<TAccountIdentity>
  {
    var jwtOptions = new JwtOptions();
    configureJwtOptions(jwtOptions);

    services.AddSingleton(jwtOptions);
    services.AddSingleton<IJwtService, JwtService>();
    services.AddScoped<IAccountIdentityStore<TAccountIdentity>, TAccountIdentityStore>();
    services.AddScoped<IAuthService<TAccountIdentity>, AuthService<TAccountIdentity>>();
    services.AddSingleton<IAuthorizationHandler, PermissionHandler>();


    services.AddAuthentication("Bearer")
        .AddJwtBearer("Bearer", options =>
        {

          options.Events = new JwtBearerEvents
          {

            OnMessageReceived = context =>
            {
              // Check for Authorization header first
              var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
              if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Bearer "))
              {
                context.Token = authHeader["Bearer ".Length..].Trim();
              }

              // Fallback to access-token cookie if no token found
              if (string.IsNullOrEmpty(context.Token) &&
                    context.Request.Cookies.TryGetValue(jwtOptions.CookieName, out var cookieToken))
              {
                context.Token = cookieToken;
              }

              return Task.CompletedTask;
            },

            OnAuthenticationFailed = context =>
            {
              Console.WriteLine("Token invalid: " + context.Exception.Message);
              return Task.CompletedTask;
            },
            OnTokenValidated = context =>
            {
              var identity = new ClaimsIdentity(
                    context.Principal!.Claims,
                    "jwt",
                    "email",
                    "role"
                );
              context.Principal = new ClaimsPrincipal(identity);
              return Task.CompletedTask;
            },
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
            ClockSkew = TimeSpan.Zero,
            RoleClaimType = ClaimTypes.Role,
            NameClaimType = ClaimTypes.Email
          };
        });


    services.AddAuthorization(options =>
    {
      if (permissionPolicies != null)
      {
        foreach (var permission in permissionPolicies)
        {
          options.AddPolicy(permission, policy =>
                      policy.Requirements.Add(new PermissionRequirement(permission)));
        }
      }
    });

    return services;
  }
}
