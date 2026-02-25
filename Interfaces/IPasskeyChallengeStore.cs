using CodeWorks.Auth.Models;

namespace CodeWorks.Auth.Interfaces;

public interface IPasskeyChallengeStore
{
  Task SaveAsync(PasskeyChallengeRecord challenge);
  Task<PasskeyChallengeRecord?> ConsumeAsync(
      string challenge,
      PasskeyChallengePurpose expectedPurpose,
      string? expectedUserId = null);
  Task CleanupExpiredAsync();
}
