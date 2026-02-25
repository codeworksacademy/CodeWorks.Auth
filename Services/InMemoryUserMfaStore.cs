using System.Collections.Concurrent;
using CodeWorks.Auth.Interfaces;

namespace CodeWorks.Auth.Services;

public class InMemoryUserMfaStore : IUserMfaStore
{
  private class MfaRecord
  {
    public string? TotpSecret { get; set; }
    public bool TotpEnabled { get; set; }
    public HashSet<string> RecoveryCodeHashes { get; } = [];
  }

  private readonly ConcurrentDictionary<string, MfaRecord> _records = new();

  public Task SetTotpSecretAsync(string userId, string secret)
  {
    var record = _records.GetOrAdd(userId, _ => new MfaRecord());
    record.TotpSecret = secret;
    return Task.CompletedTask;
  }

  public Task<string?> GetTotpSecretAsync(string userId)
  {
    _records.TryGetValue(userId, out var record);
    return Task.FromResult(record?.TotpSecret);
  }

  public Task SetTotpEnabledAsync(string userId, bool enabled)
  {
    var record = _records.GetOrAdd(userId, _ => new MfaRecord());
    record.TotpEnabled = enabled;
    return Task.CompletedTask;
  }

  public Task<bool> IsTotpEnabledAsync(string userId)
  {
    _records.TryGetValue(userId, out var record);
    return Task.FromResult(record?.TotpEnabled == true);
  }

  public Task SaveRecoveryCodeHashesAsync(string userId, IEnumerable<string> recoveryCodeHashes)
  {
    var record = _records.GetOrAdd(userId, _ => new MfaRecord());
    record.RecoveryCodeHashes.Clear();

    foreach (var code in recoveryCodeHashes.Where(c => !string.IsNullOrWhiteSpace(c)))
      record.RecoveryCodeHashes.Add(code);

    return Task.CompletedTask;
  }

  public Task<bool> ConsumeRecoveryCodeHashAsync(string userId, string recoveryCodeHash)
  {
    _records.TryGetValue(userId, out var record);
    if (record == null) return Task.FromResult(false);

    var removed = record.RecoveryCodeHashes.Remove(recoveryCodeHash);
    return Task.FromResult(removed);
  }
}
