using CodeWorks.Auth.Models;
using Microsoft.AspNetCore.Identity;

namespace CodeWorks.Auth.Interfaces;

public interface IAccountIdentity
{
  string Id { get; set; }
  string Email { get; set; }
  string Name { get; set; }
  string Picture { get; set; }

  string PasswordHash { get; set; }
  bool IsEmailVerified { get; set; }

  List<string> Roles { get; set; }
  List<string> Permissions { get; set; }
}

public interface IOAuthUser : IAccountIdentity
{
  string? Provider { get; set; }  // "google", "facebook", "local"
  string? ProviderId { get; set; } // User ID from OAuth provider
  string? ProfilePictureUrl { get; set; }
}

public interface IOAuthService<TUser> where TUser : IOAuthUser
{
  Task<AuthResult<TUser>> HandleOAuthCallbackAsync(
      ExternalLoginInfo loginInfo);

  Task<string> GenerateOAuthStateAsync(string provider);

  Task<bool> ValidateOAuthStateAsync(string state);
}