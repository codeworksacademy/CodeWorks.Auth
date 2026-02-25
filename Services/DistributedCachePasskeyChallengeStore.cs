using System.Collections.Concurrent;
using System.Text.Json;
using CodeWorks.Auth.Interfaces;
using CodeWorks.Auth.Models;
using Microsoft.Extensions.Caching.Distributed;

namespace CodeWorks.Auth.Services;

public class DistributedCachePasskeyChallengeStore : IPasskeyChallengeStore
{
  private static readonly ConcurrentDictionary<string, SemaphoreSlim> Locks = new();

  private readonly IDistributedCache _cache;
  private const string KeyPrefix = "passkey_challenge:";

  public DistributedCachePasskeyChallengeStore(IDistributedCache cache)
  {
    _cache = cache;
  }

  public async Task SaveAsync(PasskeyChallengeRecord challenge)
  {
    var json = JsonSerializer.Serialize(challenge);
    var options = new DistributedCacheEntryOptions
    {
      AbsoluteExpiration = challenge.ExpiresAt
    };

    await _cache.SetStringAsync(GetKey(challenge.Challenge), json, options);
  }

  public async Task<PasskeyChallengeRecord?> ConsumeAsync(
      string challenge,
      PasskeyChallengePurpose expectedPurpose,
      string? expectedUserId = null)
  {
    var gate = Locks.GetOrAdd(challenge, _ => new SemaphoreSlim(1, 1));
    await gate.WaitAsync();

    try
    {
      var key = GetKey(challenge);
      var json = await _cache.GetStringAsync(key);
      if (string.IsNullOrWhiteSpace(json))
        return null;

      await _cache.RemoveAsync(key);

      var record = JsonSerializer.Deserialize<PasskeyChallengeRecord>(json);
      if (record == null)
        return null;
      if (record.ExpiresAt <= DateTime.UtcNow)
        return null;
      if (record.Purpose != expectedPurpose)
        return null;

      if (!string.IsNullOrWhiteSpace(expectedUserId) &&
          !string.Equals(record.UserId, expectedUserId, StringComparison.Ordinal))
      {
        return null;
      }

      return record;
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

  private static string GetKey(string challenge) => $"{KeyPrefix}{challenge}";
}
