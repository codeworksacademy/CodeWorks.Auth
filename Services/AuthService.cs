using CodeWorks.Auth.Extensions;
using CodeWorks.Auth.Interfaces;
using CodeWorks.Auth.Models;
using CodeWorks.Auth.Security;
using Microsoft.AspNetCore.Identity;

namespace CodeWorks.Auth.Services;

public interface IAuthService<TIdentity> where TIdentity : IAccountIdentity
{
  Task<AuthResult<TIdentity>> LoginAsync(string email, string password);
  Task<AuthResult<TIdentity>> RegisterAsync(TIdentity user, string password);
  Task<AuthResult<TIdentity>> ResetPasswordAsync(string email, string newPassword);
  Task<AuthResult<TIdentity>> RefreshAuthToken(string token, int refreshExtensionInHours = 1);
  AuthResult<TIdentity> GenerateAuthToken(TIdentity user);

}

public class AuthService<TIdentity>(IAccountIdentityStore<TIdentity> store, IJwtService jwt) : IAuthService<TIdentity> where TIdentity : class, IAccountIdentity
{
  private readonly IAccountIdentityStore<TIdentity> _store = store;
  private readonly IJwtService _jwt = jwt;

  public async Task<AuthResult<TIdentity>> RegisterAsync(TIdentity user, string password)
  {
    if (await _store.EmailExistsAsync(user.Email))
      return AuthResult<TIdentity>.Failure("Email already registered.");

    user.PasswordHash = PasswordHelper<TIdentity>.HashPassword(user, password);
    await _store.SaveAsync(user);
    return AuthResult<TIdentity>.Success(user, _jwt.GenerateToken(user));
  }

  public async Task<AuthResult<TIdentity>> LoginAsync(string email, string password)
  {
    var user = await _store.FindByEmailAsync(email);
    if (user == null)
      return AuthResult<TIdentity>.Failure("Invalid credentials.");

    var result = PasswordHelper<TIdentity>.VerifyPassword(user, user.PasswordHash, password);
    if (result == PasswordVerificationResult.Failed)
      return AuthResult<TIdentity>.Failure("Invalid credentials.");

    return AuthResult<TIdentity>.Success(user, _jwt.GenerateToken(user));
  }

  public async Task<AuthResult<TIdentity>> ResetPasswordAsync(string email, string newPassword)
  {
    var user = await _store.FindByEmailAsync(email);
    if (user == null)
      return AuthResult<TIdentity>.Failure("User not found.");

    user.PasswordHash = PasswordHelper<TIdentity>.HashPassword(user, newPassword);
    await _store.SaveAsync(user);
    return AuthResult<TIdentity>.Success(user, _jwt.GenerateToken(user));
  }

  public AuthResult<TIdentity> GenerateAuthToken(TIdentity user)
  {
    if (user == null)
      return AuthResult<TIdentity>.Failure("Invalid credentials.");
    return AuthResult<TIdentity>.Success(user, _jwt.GenerateToken(user));
  }


  public async Task<AuthResult<TIdentity>> RefreshAuthToken(string token, int refreshExtensionInHours = 1)
  {
    var email = _jwt.GetEmailFromToken(token);
    var user = await _store.FindByEmailAsync(email);
    if (user == null)
      return AuthResult<TIdentity>.Failure("Invalid credentials.");

    var result = _jwt.RefreshToken(token, user, refreshExtensionInHours);
    if (result == null)
      return AuthResult<TIdentity>.Failure("Invalid token.");
    return AuthResult<TIdentity>.Success(user, result);
  }

}
