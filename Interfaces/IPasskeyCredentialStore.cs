using CodeWorks.Auth.Models;

namespace CodeWorks.Auth.Interfaces;

public interface IPasskeyCredentialStore
{
  Task SaveAsync(PasskeyCredentialRecord credential);
  Task<PasskeyCredentialRecord?> GetAsync(string credentialId);
  Task<IReadOnlyList<PasskeyCredentialRecord>> GetByUserIdAsync(string userId);
  Task UpdateUsageAsync(string credentialId, uint newSignCount, DateTime usedAtUtc);
}
