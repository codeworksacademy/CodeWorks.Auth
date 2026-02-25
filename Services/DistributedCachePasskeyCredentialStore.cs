using System.Collections.Concurrent;
using System.Text.Json;
using CodeWorks.Auth.Interfaces;
using CodeWorks.Auth.Models;
using Microsoft.Extensions.Caching.Distributed;

namespace CodeWorks.Auth.Services;

public class DistributedCachePasskeyCredentialStore : IPasskeyCredentialStore
{
  private static readonly ConcurrentDictionary<string, SemaphoreSlim> Locks = new();

  private readonly IDistributedCache _cache;
  private const string CredentialPrefix = "passkey_credential:";
  private const string UserCredentialIndexPrefix = "passkey_user_credentials:";

  public DistributedCachePasskeyCredentialStore(IDistributedCache cache)
  {
    _cache = cache;
  }

  public async Task SaveAsync(PasskeyCredentialRecord credential)
  {
    var credentialKey = GetCredentialKey(credential.CredentialId);
    var credentialJson = JsonSerializer.Serialize(credential);
    await _cache.SetStringAsync(credentialKey, credentialJson);

    var userIndexKey = GetUserIndexKey(credential.UserId);
    var gate = Locks.GetOrAdd(userIndexKey, _ => new SemaphoreSlim(1, 1));
    await gate.WaitAsync();

    try
    {
      var existingJson = await _cache.GetStringAsync(userIndexKey);
      var ids = string.IsNullOrWhiteSpace(existingJson)
          ? []
          : JsonSerializer.Deserialize<List<string>>(existingJson) ?? [];

      if (!ids.Contains(credential.CredentialId, StringComparer.Ordinal))
      {
        ids.Add(credential.CredentialId);
        await _cache.SetStringAsync(userIndexKey, JsonSerializer.Serialize(ids));
      }
    }
    finally
    {
      gate.Release();
    }
  }

  public async Task<PasskeyCredentialRecord?> GetAsync(string credentialId)
  {
    var json = await _cache.GetStringAsync(GetCredentialKey(credentialId));
    if (string.IsNullOrWhiteSpace(json))
      return null;

    return JsonSerializer.Deserialize<PasskeyCredentialRecord>(json);
  }

  public async Task<IReadOnlyList<PasskeyCredentialRecord>> GetByUserIdAsync(string userId)
  {
    var idsJson = await _cache.GetStringAsync(GetUserIndexKey(userId));
    if (string.IsNullOrWhiteSpace(idsJson))
      return [];

    var ids = JsonSerializer.Deserialize<List<string>>(idsJson) ?? [];
    if (ids.Count == 0)
      return [];

    var credentials = new List<PasskeyCredentialRecord>(ids.Count);
    var activeIds = new List<string>(ids.Count);

    foreach (var id in ids.Distinct(StringComparer.Ordinal))
    {
      var credential = await GetAsync(id);
      if (credential == null)
        continue;

      credentials.Add(credential);
      activeIds.Add(id);
    }

    if (activeIds.Count != ids.Count)
      await _cache.SetStringAsync(GetUserIndexKey(userId), JsonSerializer.Serialize(activeIds));

    return credentials;
  }

  public async Task UpdateUsageAsync(string credentialId, uint newSignCount, DateTime usedAtUtc)
  {
    var gate = Locks.GetOrAdd(GetCredentialKey(credentialId), _ => new SemaphoreSlim(1, 1));
    await gate.WaitAsync();

    try
    {
      var credential = await GetAsync(credentialId);
      if (credential == null)
        return;

      credential.SignCount = newSignCount;
      credential.LastUsedAt = usedAtUtc;
      await _cache.SetStringAsync(GetCredentialKey(credentialId), JsonSerializer.Serialize(credential));
    }
    finally
    {
      gate.Release();
    }
  }

  private static string GetCredentialKey(string credentialId) => $"{CredentialPrefix}{credentialId}";
  private static string GetUserIndexKey(string userId) => $"{UserCredentialIndexPrefix}{userId}";
}
