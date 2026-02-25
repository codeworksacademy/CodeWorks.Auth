using CodeWorks.Auth.Interfaces;

namespace CodeWorks.Auth.Services;

public class NoOpAuthAbuseProtector : IAuthAbuseProtector
{
  public Task<bool> IsLoginAllowedAsync(string email) => Task.FromResult(true);
  public Task RecordFailedLoginAsync(string email) => Task.CompletedTask;
  public Task RecordSuccessfulLoginAsync(string email) => Task.CompletedTask;
}
