using System.Collections.Concurrent;
using CodeWorks.Auth.Interfaces;
using CodeWorks.Auth.Models;

namespace CodeWorks.Auth.Services;

public class InMemoryPasskeyChallengeStore : IPasskeyChallengeStore
{
  private readonly ConcurrentDictionary<string, PasskeyChallengeRecord> _challenges = new();
  private readonly SemaphoreSlim _gate = new(1, 1);

  public Task SaveAsync(PasskeyChallengeRecord challenge)
  {
    _challenges[challenge.Challenge] = challenge;
    return Task.CompletedTask;
  }

  public async Task<PasskeyChallengeRecord?> ConsumeAsync(
      string challenge,
      PasskeyChallengePurpose expectedPurpose,
      string? expectedUserId = null)
  {
    await _gate.WaitAsync();
    try
    {
      if (!_challenges.TryGetValue(challenge, out var value) || value == null)
        return null;

      _challenges.TryRemove(challenge, out _);

      if (value.ExpiresAt < DateTime.UtcNow)
        return null;
      if (value.Purpose != expectedPurpose)
        return null;
      if (!string.IsNullOrWhiteSpace(expectedUserId) &&
          !string.Equals(value.UserId, expectedUserId, StringComparison.Ordinal))
      {
        return null;
      }

      return value;
    }
    finally
    {
      _gate.Release();
    }
  }

  public Task CleanupExpiredAsync()
  {
    var now = DateTime.UtcNow;
    var expiredKeys = _challenges
        .Where(kvp => kvp.Value.ExpiresAt <= now)
        .Select(kvp => kvp.Key)
        .ToList();

    foreach (var key in expiredKeys)
      _challenges.TryRemove(key, out _);

    return Task.CompletedTask;
  }
}
