using CodeWorks.Auth.Interfaces;
using CodeWorks.Auth.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace CodeWorks.Auth.Services;

public class AuthStoreCleanupService : BackgroundService
{
  private readonly IServiceProvider _serviceProvider;
  private readonly AuthStoreOptions _options;
  private readonly ILogger<AuthStoreCleanupService> _logger;

  public AuthStoreCleanupService(
      IServiceProvider serviceProvider,
      AuthStoreOptions options,
      ILogger<AuthStoreCleanupService> logger)
  {
    _serviceProvider = serviceProvider;
    _options = options;
    _logger = logger;
  }

  protected override async Task ExecuteAsync(CancellationToken stoppingToken)
  {
    _logger.LogInformation("Auth store cleanup service started");

    while (!stoppingToken.IsCancellationRequested)
    {
      try
      {
        await Task.Delay(_options.CleanupInterval, stoppingToken);

        using var scope = _serviceProvider.CreateScope();
        var refreshStore = scope.ServiceProvider.GetRequiredService<IRefreshTokenStore>();
        var challengeStore = scope.ServiceProvider.GetRequiredService<IPasskeyChallengeStore>();

        await refreshStore.CleanupExpiredAsync();
        await challengeStore.CleanupExpiredAsync();
      }
      catch (OperationCanceledException)
      {
        break;
      }
      catch (Exception ex)
      {
        _logger.LogError(ex, "Error during auth store cleanup");
      }
    }

    _logger.LogInformation("Auth store cleanup service stopped");
  }
}
