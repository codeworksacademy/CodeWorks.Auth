using System.Collections.Concurrent;
using CodeWorks.Auth.Interfaces;
using CodeWorks.Auth.Models;

namespace CodeWorks.Auth.Services;

public class InMemoryPasskeyChallengeStore : IPasskeyChallengeStore
{
  private readonly ConcurrentDictionary<string, PasskeyChallengeRecord> _challenges = new();

  public Task SaveAsync(PasskeyChallengeRecord challenge)
  {
    _challenges[challenge.Challenge] = challenge;
    return Task.CompletedTask;
  }

  public Task<PasskeyChallengeRecord?> GetAsync(string challenge)
  {
    _challenges.TryGetValue(challenge, out var value);
    return Task.FromResult(value);
  }

  public Task DeleteAsync(string challenge)
  {
    _challenges.TryRemove(challenge, out _);
    return Task.CompletedTask;
  }
}
