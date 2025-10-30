using CodeWorks.Auth.Models;
using Microsoft.AspNetCore.Identity;

namespace CodeWorks.Auth.Interfaces;

public interface IOAuthService<TIdentity> where TIdentity : IAccountIdentity, new()
{
  Task<AuthResult<TIdentity>> HandleOAuthCallbackAsync(ExternalLoginInfo loginInfo);
  Task<string> GenerateOAuthStateAsync(string provider, string? returnUrl = null);
  Task<bool> ValidateOAuthStateAsync(string state);
}