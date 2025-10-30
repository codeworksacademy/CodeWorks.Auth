using CodeWorks.Auth.Interfaces;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace CodeWorks.Auth.Services;

/// <summary>
/// Database implementation for OAuth state store
/// Best for persistence and audit trail requirements
/// </summary>
// public class DatabaseOAuthStateStore : IOAuthStateStore
// {
//     private readonly IDbConnection _db;
//     private readonly ILogger<DatabaseOAuthStateStore> _logger;

//     public DatabaseOAuthStateStore(
//         IDbConnection db,
//         ILogger<DatabaseOAuthStateStore> logger)
//     {
//         _db = db;
//         _logger = logger;
//     }

//     public async Task StoreStateAsync(OAuthState state)
//     {
//         const string sql = @"
//             INSERT INTO oauth_states (token, provider, return_url, created_at, expires_at, is_used)
//             VALUES (@Token, @Provider, @ReturnUrl, @CreatedAt, @ExpiresAt, @IsUsed)";

//         await _db.ExecuteAsync(sql, state);
//         _logger.LogDebug("Stored OAuth state in database: {Token}", state.Token);
//     }

//     public async Task<OAuthState?> GetStateAsync(string token)
//     {
//         const string sql = @"
//             SELECT token, provider, return_url as ReturnUrl, created_at as CreatedAt, 
//                    expires_at as ExpiresAt, is_used as IsUsed
//             FROM oauth_states 
//             WHERE token = @token";

//         return await _db.QueryFirstOrDefaultAsync<OAuthState>(sql, new { token });
//     }

//     public async Task UpdateStateAsync(OAuthState state)
//     {
//         const string sql = @"
//             UPDATE oauth_states 
//             SET is_used = @IsUsed, return_url = @ReturnUrl
//             WHERE token = @Token";

//         await _db.ExecuteAsync(sql, state);
//         _logger.LogDebug("Updated OAuth state in database: {Token}", state.Token);
//     }

//     public async Task DeleteStateAsync(string token)
//     {
//         const string sql = "DELETE FROM oauth_states WHERE token = @token";
//         await _db.ExecuteAsync(sql, new { token });
//         _logger.LogDebug("Deleted OAuth state from database: {Token}", token);
//     }

//     public async Task CleanupExpiredStatesAsync()
//     {
//         const string sql = "DELETE FROM oauth_states WHERE expires_at < @now";
//         var deletedCount = await _db.ExecuteAsync(sql, new { now = DateTime.UtcNow });

//         if (deletedCount > 0)
//         {
//             _logger.LogInformation("Cleaned up {Count} expired OAuth states from database", deletedCount);
//         }
//     }
// }

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