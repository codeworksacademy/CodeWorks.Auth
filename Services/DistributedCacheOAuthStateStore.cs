using System.Text.Json;
using CodeWorks.Auth.Interfaces;
using CodeWorks.Auth.Models;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;

namespace CodeWorks.Auth.Services;

/// <summary>
/// Distributed cache implementation for multi-instance deployments
/// Requires Redis or similar distributed cache
/// </summary>
public class DistributedCacheOAuthStateStore : IOAuthStateStore
{
    private readonly IDistributedCache _cache;
    private readonly ILogger<DistributedCacheOAuthStateStore> _logger;
    private const string KeyPrefix = "oauth_state:";

    public DistributedCacheOAuthStateStore(
        IDistributedCache cache,
        ILogger<DistributedCacheOAuthStateStore> logger)
    {
        _cache = cache;
        _logger = logger;
    }

    public async Task StoreStateAsync(OAuthState state)
    {
        var key = GetKey(state.Token);
        var json = JsonSerializer.Serialize(state);
        
        var options = new DistributedCacheEntryOptions
        {
            AbsoluteExpiration = state.ExpiresAt
        };

        await _cache.SetStringAsync(key, json, options);
        _logger.LogDebug("Stored OAuth state in distributed cache");
    }

    public async Task<OAuthState?> GetStateAsync(string token)
    {
        var key = GetKey(token);
        var json = await _cache.GetStringAsync(key);

        if (string.IsNullOrEmpty(json))
        {
            return null;
        }

        return JsonSerializer.Deserialize<OAuthState>(json);
    }

    public async Task UpdateStateAsync(OAuthState state)
    {
        await StoreStateAsync(state); // Simply overwrite in cache
    }

    public async Task<OAuthState?> ConsumeStateAsync(string token, string? expectedProvider = null)
    {
        var key = GetKey(token);
        var json = await _cache.GetStringAsync(key);
        if (string.IsNullOrWhiteSpace(json))
        {
            return null;
        }

        var state = JsonSerializer.Deserialize<OAuthState>(json);
        if (state == null || state.IsUsed || state.ExpiresAt < DateTime.UtcNow)
        {
            await _cache.RemoveAsync(key);
            return null;
        }

        if (!string.IsNullOrWhiteSpace(expectedProvider) &&
            !string.Equals(state.Provider, expectedProvider, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        state.IsUsed = true;
        await _cache.RemoveAsync(key);
        return state;
    }

    public async Task DeleteStateAsync(string token)
    {
        var key = GetKey(token);
        await _cache.RemoveAsync(key);
        _logger.LogDebug("Deleted OAuth state from distributed cache");
    }

    public Task CleanupExpiredStatesAsync()
    {
        // Distributed cache automatically removes expired entries
        return Task.CompletedTask;
    }

    private static string GetKey(string token) => $"{KeyPrefix}{token}";
}
