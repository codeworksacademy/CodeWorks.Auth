namespace CodeWorks.Auth.Interfaces;

public interface IAuthAbuseProtector
{
  Task<bool> IsLoginAllowedAsync(string email);
  Task RecordFailedLoginAsync(string email);
  Task RecordSuccessfulLoginAsync(string email);
}
