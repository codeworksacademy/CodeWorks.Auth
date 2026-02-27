using CodeWorks.Auth.Interfaces;

namespace CodeWorks.Auth.MvcSample.Models;

public class AppUser : IAccountIdentity<string>
{
  public string Id { get; set; } = Guid.NewGuid().ToString("N");
  public string Email { get; set; } = string.Empty;
  public string Name { get; set; } = string.Empty;
  public string Picture { get; set; } = string.Empty;
  public string PasswordHash { get; set; } = string.Empty;
  public bool IsEmailVerified { get; set; }
  public string? Provider { get; set; }
  public string? ProviderId { get; set; }
  public string? ProfilePictureUrl { get; set; }
  public DateTime? LastLoginAt { get; set; }
  public List<string> Roles { get; set; } = ["User"];
  public List<string> Permissions { get; set; } = ["CanReadAccount"];
}
