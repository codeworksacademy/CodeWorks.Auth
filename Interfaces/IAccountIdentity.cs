namespace CodeWorks.Auth.Interfaces;

public interface IAccountIdentity
{
  string Id { get; set; }
  string Email { get; set; }
  string? Name { get; set; }
  string? Picture { get; set; }

  string PasswordHash { get; set; }
  bool IsEmailVerified { get; set; }

  List<string> Roles { get; set; }
  List<string> Permissions { get; set; }
}
