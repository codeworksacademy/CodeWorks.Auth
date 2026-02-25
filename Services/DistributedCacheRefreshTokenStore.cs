using System.Collections.Concurrent;
using System.Text.Json;
using CodeWorks.Auth.Interfaces;
using CodeWorks.Auth.Models;
using Microsoft.Extensions.Caching.Distributed;

namespace CodeWorks.Auth.Services;

public class DistributedCacheRefreshTokenStore : IRefreshTokenStore
{
  private static readonly ConcurrentDictionary<string, SemaphoreSlim> Locks = new();

  private readonly IDistributedCache _cache;
  private readonly AuthStoreOptions _storeOptions;
  private const string KeyPrefix = "refresh_token:";

  public DistributedCacheRefreshTokenStore(IDistributedCache cache, AuthStoreOptions storeOptions)
  {
    _cache = cache;
    _storeOptions = storeOptions;
  }

  public Task SaveTokenAsync(RefreshTokenRecord token)
  {
    return SaveInternalAsync(token, ResolveAbsoluteExpiration(token));
  }

  public async Task<RefreshTokenRecord?> GetTokenAsync(string tokenHash)
  {
    var json = await _cache.GetStringAsync(GetKey(tokenHash));
    if (string.IsNullOrWhiteSpace(json))
      return null;

    return JsonSerializer.Deserialize<RefreshTokenRecord>(json);
  }

  public async Task<RefreshTokenRecord?> TryConsumeActiveTokenAsync(string tokenHash)
  {
    var gate = Locks.GetOrAdd(tokenHash, _ => new SemaphoreSlim(1, 1));
    await gate.WaitAsync();

    try
    {
      var record = await GetTokenAsync(tokenHash);
      if (record == null)
        return null;

      if (!record.IsActive)
      {
        if (record.ExpiresAt <= DateTime.UtcNow)
          await _cache.RemoveAsync(GetKey(tokenHash));
        return null;
      }

      record.RevokedAt = DateTime.UtcNow;
      await SaveInternalAsync(record, ResolveAbsoluteExpiration(record));
      return record;
    }
    finally
    {
      gate.Release();
    }
  }

  public async Task RevokeTokenAsync(string tokenHash, string? replacedByTokenHash = null)
  {
    var gate = Locks.GetOrAdd(tokenHash, _ => new SemaphoreSlim(1, 1));
    await gate.WaitAsync();

    try
    {
      var record = await GetTokenAsync(tokenHash);
      if (record == null)
        return;

      record.RevokedAt = DateTime.UtcNow;
      record.ReplacedByTokenHash = replacedByTokenHash;
      await SaveInternalAsync(record, ResolveAbsoluteExpiration(record));
    }
    finally
    {
      gate.Release();
    }
  }

  public Task CleanupExpiredAsync()
  {
    return Task.CompletedTask;
  }

  private async Task SaveInternalAsync(RefreshTokenRecord token, DateTimeOffset absoluteExpiration)
  {
    var json = JsonSerializer.Serialize(token);
    var options = new DistributedCacheEntryOptions
    {
      AbsoluteExpiration = absoluteExpiration
    };

    await _cache.SetStringAsync(GetKey(token.TokenHash), json, options);
  }

  private DateTimeOffset ResolveAbsoluteExpiration(RefreshTokenRecord token)
  {
    var now = DateTime.UtcNow;
    if (token.RevokedAt.HasValue)
    {
      var retentionUntil = now.Add(_storeOptions.RevokedTokenRetention);
      return token.ExpiresAt > retentionUntil ? token.ExpiresAt : retentionUntil;
    }

    return token.ExpiresAt;
  }

  private static string GetKey(string tokenHash) => $"{KeyPrefix}{tokenHash}";
}
