using CWAuth.Extensions;
using CWAuth.Interfaces;
using CWAuth.Security;
using Microsoft.AspNetCore.Identity;

namespace CWAuth.Services;

public interface IAuthService<TIdentity> where TIdentity : IAccountIdentity
{
  Task<AuthResult> LoginAsync(string email, string password);
  Task<AuthResult> RegisterAsync(TIdentity user, string password);
  Task<AuthResult> ResetPasswordAsync(string email, string newPassword);
}

public class AuthService<TIdentity> : IAuthService<TIdentity> where TIdentity : class, IAccountIdentity
{
  private readonly IAccountIdentityStore<TIdentity> _store;
  private readonly IJwtService _jwt;

  public AuthService(IAccountIdentityStore<TIdentity> store, IJwtService jwt)
  {
    _store = store;
    _jwt = jwt;
  }

  public async Task<AuthResult> RegisterAsync(TIdentity user, string password)
  {
    if (await _store.EmailExistsAsync(user.Email))
      return AuthResult.Failure("Email already registered.");

    user.PasswordHash = PasswordHelper<IAccountIdentity>.HashPassword(user, password);
    await _store.SaveAsync(user);
    return AuthResult.Success(user, _jwt.GenerateToken(user));
  }

  public async Task<AuthResult> LoginAsync(string email, string password)
  {
    var user = await _store.FindByEmailAsync(email);
    if (user == null)
      return AuthResult.Failure("Invalid credentials.");

    var result = PasswordHelper<IAccountIdentity>.VerifyPassword(user, user.PasswordHash, password);
    if (result == PasswordVerificationResult.Failed)
      return AuthResult.Failure("Invalid credentials.");

    return AuthResult.Success(user, _jwt.GenerateToken(user));
  }

  public async Task<AuthResult> ResetPasswordAsync(string email, string newPassword)
  {
    var user = await _store.FindByEmailAsync(email);
    if (user == null)
      return AuthResult.Failure("User not found.");

    user.PasswordHash = PasswordHelper<IAccountIdentity>.HashPassword(user, newPassword);
    await _store.SaveAsync(user);
    return AuthResult.Success(user, _jwt.GenerateToken(user));
  }

}
