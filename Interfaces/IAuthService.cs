using CodeWorks.Auth.Models;

namespace CodeWorks.Auth.Interfaces;

public interface IAuthService<TIdentity> where TIdentity : IAccountIdentity
{
  Task<AuthResult<TIdentity>> LoginAsync(string email, string password);
  Task<AuthResult<TIdentity>> RegisterAsync(TIdentity user, string password);
  Task<AuthResult<TIdentity>> ResetPasswordAsync(string email, string newPassword);
  Task<AuthResult<TIdentity>> RefreshAuthToken(string token, int refreshExtensionInHours = 1);
  AuthResult<TIdentity> GenerateAuthToken(TIdentity user);

}