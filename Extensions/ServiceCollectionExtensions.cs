using CWAuth.Interfaces;
using CWAuth.Security;
using CWAuth.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;

namespace CWAuth.Extensions;

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