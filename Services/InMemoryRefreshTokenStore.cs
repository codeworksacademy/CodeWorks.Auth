using System.Collections.Concurrent;
using CodeWorks.Auth.Interfaces;
using CodeWorks.Auth.Models;

namespace CodeWorks.Auth.Services;

public class InMemoryRefreshTokenStore : IRefreshTokenStore
{
  private readonly ConcurrentDictionary<string, RefreshTokenRecord> _tokens = new();
  private readonly SemaphoreSlim _gate = new(1, 1);

  public Task SaveTokenAsync(RefreshTokenRecord token)
  {
    _tokens[token.TokenHash] = token;
    return Task.CompletedTask;
  }

  public Task<RefreshTokenRecord?> GetTokenAsync(string tokenHash)
  {
    _tokens.TryGetValue(tokenHash, out var token);
    return Task.FromResult(token);
  }

  public async Task<RefreshTokenRecord?> TryConsumeActiveTokenAsync(string tokenHash)
  {
    await _gate.WaitAsync();
    try
    {
      if (!_tokens.TryGetValue(tokenHash, out var token) || token == null)
        return null;

      if (!token.IsActive)
      {
        if (token.ExpiresAt <= DateTime.UtcNow)
          _tokens.TryRemove(tokenHash, out _);
        return null;
      }

      token.RevokedAt = DateTime.UtcNow;
      _tokens[tokenHash] = token;
      return token;
    }
    finally
    {
      _gate.Release();
    }
  }

  public Task RevokeTokenAsync(string tokenHash, string? replacedByTokenHash = null)
  {
    if (_tokens.TryGetValue(tokenHash, out var token))
    {
      token.RevokedAt = DateTime.UtcNow;
      token.ReplacedByTokenHash = replacedByTokenHash;
      _tokens[tokenHash] = token;
    }

    return Task.CompletedTask;
  }

  public Task CleanupExpiredAsync()
  {
    var now = DateTime.UtcNow;
    var staleKeys = _tokens
        .Where(kvp => kvp.Value.ExpiresAt <= now)
        .Select(kvp => kvp.Key)
        .ToList();

    foreach (var key in staleKeys)
      _tokens.TryRemove(key, out _);

    return Task.CompletedTask;
  }
}
