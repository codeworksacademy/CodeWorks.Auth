using System.Collections.Concurrent;
using CodeWorks.Auth.Interfaces;
using CodeWorks.Auth.Models;

namespace CodeWorks.Auth.Services;

public class InMemoryRefreshTokenStore : IRefreshTokenStore
{
  private readonly ConcurrentDictionary<string, RefreshTokenRecord> _tokens = new();

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
}
