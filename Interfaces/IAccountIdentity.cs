namespace CodeWorks.Auth.Interfaces;

public interface IAccountIdentityBase
{
  string IdAsString { get; }
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

public interface IAccountIdentity<TId> : IAccountIdentityBase where TId : notnull
{
  TId Id { get; set; }

  string IAccountIdentityBase.IdAsString => Id?.ToString() ?? string.Empty;
}

public interface IAccountIdentity : IAccountIdentity<string>
{
}
