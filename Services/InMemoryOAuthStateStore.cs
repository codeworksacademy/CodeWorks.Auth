using System.Collections.Concurrent;
using System.Data;
using CodeWorks.Auth.Interfaces;
using CodeWorks.Auth.Models;
using Microsoft.Extensions.Logging;

namespace CodeWorks.Auth.Services;

/// <summary>
/// In-memory implementation of OAuth state store
/// Best for single-instance deployments or development
/// </summary>
public class InMemoryOAuthStateStore : IOAuthStateStore
{
    private readonly ConcurrentDictionary<string, OAuthState> _states = new();
    private readonly ILogger<InMemoryOAuthStateStore> _logger;

    public InMemoryOAuthStateStore(ILogger<InMemoryOAuthStateStore> logger)
    {
        _logger = logger;
    }

    public Task StoreStateAsync(OAuthState state)
    {
        if (_states.TryAdd(state.Token, state))
        {
            _logger.LogDebug("Stored OAuth state");
            return Task.CompletedTask;
        }

        throw new InvalidOperationException($"Failed to store OAuth state: {state.Token}");
    }

    public Task<OAuthState?> GetStateAsync(string token)
    {
        _states.TryGetValue(token, out var state);
        return Task.FromResult(state);
    }

    public Task UpdateStateAsync(OAuthState state)
    {
        _states[state.Token] = state;
        _logger.LogDebug("Updated OAuth state");
        return Task.CompletedTask;
    }

    public Task<OAuthState?> ConsumeStateAsync(string token, string? expectedProvider = null)
    {
        if (!_states.TryRemove(token, out var state) || state == null)
        {
            return Task.FromResult<OAuthState?>(null);
        }

        if (state.ExpiresAt < DateTime.UtcNow || state.IsUsed)
        {
            return Task.FromResult<OAuthState?>(null);
        }

        if (!string.IsNullOrWhiteSpace(expectedProvider) &&
            !string.Equals(state.Provider, expectedProvider, StringComparison.OrdinalIgnoreCase))
        {
            return Task.FromResult<OAuthState?>(null);
        }

        state.IsUsed = true;
        return Task.FromResult<OAuthState?>(state);
    }

    public Task DeleteStateAsync(string token)
    {
        _states.TryRemove(token, out _);
        _logger.LogDebug("Deleted OAuth state");
        return Task.CompletedTask;
    }

    public Task CleanupExpiredStatesAsync()
    {
        var now = DateTime.UtcNow;
        var expiredTokens = _states
            .Where(kvp => kvp.Value.ExpiresAt < now)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var token in expiredTokens)
        {
            _states.TryRemove(token, out _);
        }

        if (expiredTokens.Count > 0)
        {
            _logger.LogInformation("Cleaned up {Count} expired OAuth states", expiredTokens.Count);
        }

        return Task.CompletedTask;
    }
}
