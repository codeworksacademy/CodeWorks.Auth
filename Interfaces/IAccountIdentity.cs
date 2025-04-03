namespace CWAuth.Interfaces;

public interface IAccountIdentity
{
  string Id { get; }
  string Email { get; }
  string? Picture { get; }
  string PasswordHash { get; set; }
  bool IsEmailVerified { get; set; }

  IEnumerable<string> Roles { get; }
  IEnumerable<string> Permissions { get; }
}
