using CodeWorks.Auth.Interfaces;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace CodeWorks.Auth.Services;

/// <summary>
/// Background service to periodically clean up expired states
/// Register as a hosted service in Program.cs
/// </summary>
public class OAuthStateCleanupService : BackgroundService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<OAuthStateCleanupService> _logger;
    private readonly TimeSpan _interval = TimeSpan.FromMinutes(5);

    public OAuthStateCleanupService(
        IServiceProvider serviceProvider,
        ILogger<OAuthStateCleanupService> logger)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("OAuth State Cleanup Service started");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(_interval, stoppingToken);

                using var scope = _serviceProvider.CreateScope();
                var stateStore = scope.ServiceProvider.GetRequiredService<IOAuthStateStore>();
                
                await stateStore.CleanupExpiredStatesAsync();
            }
            catch (OperationCanceledException)
            {
                // Expected when service is stopping
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during OAuth state cleanup");
            }
        }

        _logger.LogInformation("OAuth State Cleanup Service stopped");
    }
}