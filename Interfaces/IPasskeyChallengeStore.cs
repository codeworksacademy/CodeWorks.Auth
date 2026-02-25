using CodeWorks.Auth.Models;

namespace CodeWorks.Auth.Interfaces;

public interface IPasskeyChallengeStore
{
  Task SaveAsync(PasskeyChallengeRecord challenge);
  Task<PasskeyChallengeRecord?> GetAsync(string challenge);
  Task DeleteAsync(string challenge);
}
