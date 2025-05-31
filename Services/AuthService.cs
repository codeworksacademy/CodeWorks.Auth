using CodeWorks.Auth.Extensions;
using CodeWorks.Auth.Interfaces;
using CodeWorks.Auth.Security;
using Microsoft.AspNetCore.Identity;

namespace CodeWorks.Auth.Services;

public interface IAuthService<TIdentity> where TIdentity : IAccountIdentity
{
  Task<AuthResult> LoginAsync(string email, string password);
  Task<AuthResult> RegisterAsync(TIdentity user, string password);
  Task<AuthResult> ResetPasswordAsync(string email, string newPassword);
  Task<AuthResult> RefreshAuthToken(string token, int refreshExtensionInHours = 1);
  AuthResult GenerateAuthToken(IAccountIdentity user);

}

public class AuthService<TIdentity>(IAccountIdentityStore<TIdentity> store, IJwtService jwt) : IAuthService<TIdentity> where TIdentity : class, IAccountIdentity
{
  private readonly IAccountIdentityStore<TIdentity> _store = store;
  private readonly IJwtService _jwt = jwt;

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

  public AuthResult GenerateAuthToken(IAccountIdentity user)
  {
    if (user == null)
      return AuthResult.Failure("Invalid credentials.");
    return AuthResult.Success(user, _jwt.GenerateToken(user));
  }


  public async Task<AuthResult> RefreshAuthToken(string token, int refreshExtensionInHours = 1)
  {
    var email = _jwt.GetEmailFromToken(token);
    var user = await _store.FindByEmailAsync(email);
    if (user == null)
      return AuthResult.Failure("Invalid credentials.");

    var result = _jwt.RefreshToken(token, user, refreshExtensionInHours);
    if (result == null)
      return AuthResult.Failure("Invalid token.");
    return AuthResult.Success(user, result);
  }

}
