using CodeWorks.Auth.Extensions;
using CodeWorks.Auth.Interfaces;
using CodeWorks.Auth.MvcSample.Models;
using CodeWorks.Auth.MvcSample.Services;
using CodeWorks.Auth.MvcSample.Stores;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace CodeWorks.Auth.MvcSample;

public class Startup
{
  public Startup(IConfiguration configuration)
  {
    Configuration = configuration;
  }

  public IConfiguration Configuration { get; }

  public void ConfigureServices(IServiceCollection services)
  {
    services.AddControllers();

    services.AddAuthModule<AppUser, AppUserStore>(
      options =>
      {
        options.SigningKey = Configuration["Jwt:Key"] ?? "change-this-to-a-long-random-secret-at-least-32-characters";
        options.Issuer = "mvc-sample-api";
        options.Audience = "mvc-sample-clients";
        options.Expiration = TimeSpan.FromHours(1);
        options.RefreshTokenExpiration = TimeSpan.FromDays(14);
      },
      permissionPolicies: ["CanReadAccount"]);

    services.AddScoped<IUserTokenStore, InMemoryUserTokenStore>();
    services.AddScoped<IUserEmailSender, ConsoleUserEmailSender>();
  }

  public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
  {
    if (env.IsDevelopment())
    {
      app.UseDeveloperExceptionPage();
    }

    app.UseRouting();
    app.UseAuthentication();
    app.UseAuthorization();

    app.UseEndpoints(endpoints =>
    {
      endpoints.MapControllers();
    });
  }
}
