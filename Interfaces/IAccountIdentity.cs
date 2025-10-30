namespace CodeWorks.Auth.Interfaces;

public interface IAccountIdentity
{
  string Id { get; set; }
  string Email { get; set; }
  string Name { get; set; }
  string Picture { get; set; }

  string PasswordHash { get; set; }
  bool IsEmailVerified { get; set; }
  string? Provider { get; set; }  // "google", "facebook", "local"
  string? ProviderId { get; set; } // User ID from OAuth provider
  string? ProfilePictureUrl { get; set; }

  DateTime? LastLoginAt { get; set; }

  List<string> Roles { get; set; }
  List<string> Permissions { get; set; }
}
