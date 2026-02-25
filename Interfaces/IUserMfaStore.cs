namespace CodeWorks.Auth.Interfaces;

public interface IUserMfaStore
{
  Task SetTotpSecretAsync(string userId, string secret);
  Task<string?> GetTotpSecretAsync(string userId);
  Task SetTotpEnabledAsync(string userId, bool enabled);
  Task<bool> IsTotpEnabledAsync(string userId);

  Task SaveRecoveryCodeHashesAsync(string userId, IEnumerable<string> recoveryCodeHashes);
  Task<bool> ConsumeRecoveryCodeHashAsync(string userId, string recoveryCodeHash);
}
