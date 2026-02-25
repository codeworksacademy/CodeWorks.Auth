using System.Collections.Concurrent;
using CodeWorks.Auth.Interfaces;
using CodeWorks.Auth.Models;

namespace CodeWorks.Auth.Services;

public class InMemoryPasskeyCredentialStore : IPasskeyCredentialStore
{
  private readonly ConcurrentDictionary<string, PasskeyCredentialRecord> _credentials = new();

  public Task SaveAsync(PasskeyCredentialRecord credential)
  {
    _credentials[credential.CredentialId] = credential;
    return Task.CompletedTask;
  }

  public Task<PasskeyCredentialRecord?> GetAsync(string credentialId)
  {
    _credentials.TryGetValue(credentialId, out var value);
    return Task.FromResult(value);
  }

  public Task<IReadOnlyList<PasskeyCredentialRecord>> GetByUserIdAsync(string userId)
  {
    var results = _credentials.Values.Where(x => x.UserId == userId).ToList();
    return Task.FromResult<IReadOnlyList<PasskeyCredentialRecord>>(results);
  }

  public Task UpdateUsageAsync(string credentialId, uint newSignCount, DateTime usedAtUtc)
  {
    if (_credentials.TryGetValue(credentialId, out var value))
    {
      value.SignCount = newSignCount;
      value.LastUsedAt = usedAtUtc;
      _credentials[credentialId] = value;
    }

    return Task.CompletedTask;
  }
}
