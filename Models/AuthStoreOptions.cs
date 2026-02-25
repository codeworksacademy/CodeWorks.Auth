namespace CodeWorks.Auth.Models;

public class AuthStoreOptions
{
  public TimeSpan CleanupInterval { get; set; } = TimeSpan.FromMinutes(5);
  public TimeSpan RevokedTokenRetention { get; set; } = TimeSpan.FromHours(12);
}
