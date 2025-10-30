using CodeWorks.Auth.Models;
using Microsoft.AspNetCore.Identity;

namespace CodeWorks.Auth.Interfaces;

public interface IOAuthService<TUser> where TUser : IAccountIdentity
{
  Task<AuthResult<TUser>> HandleOAuthCallbackAsync(
      ExternalLoginInfo loginInfo);

  Task<string> GenerateOAuthStateAsync(string provider);

  Task<bool> ValidateOAuthStateAsync(string state);
}