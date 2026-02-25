using CodeWorks.Auth.Extensions;
using CodeWorks.Auth.Interfaces;
using CodeWorks.Auth.Models;
using CodeWorks.Auth.Security;
using Microsoft.AspNetCore.Identity;

namespace CodeWorks.Auth.Services;

public class AuthService<TIdentity> : IAuthService<TIdentity> where TIdentity : class, IAccountIdentityBase
{
  private readonly IAccountIdentityStore<TIdentity> _store;
  private readonly IJwtService _jwt;
  private readonly IRefreshTokenService<TIdentity> _refreshTokenService;
  private readonly IAuthAbuseProtector _abuseProtector;

  public AuthService(
      IAccountIdentityStore<TIdentity> store,
      IJwtService jwt,
      IRefreshTokenService<TIdentity> refreshTokenService,
      IAuthAbuseProtector abuseProtector)
  {
    _store = store;
    _jwt = jwt;
    _refreshTokenService = refreshTokenService;
    _abuseProtector = abuseProtector;
  }

  public async Task<AuthResult<TIdentity>> RegisterAsync(TIdentity userData, string password)
  {
    if (await _store.EmailExistsAsync(userData.Email))
      return AuthResult<TIdentity>.Failure("Email already registered.");

    userData.PasswordHash = PasswordHelper<TIdentity>.HashPassword(userData, password);
    var user = await _store.CreateAsync(userData);
    return AuthResult<TIdentity>.Success(user, _jwt.GenerateToken(user));
  }

  public async Task<AuthSessionResult<TIdentity>> RegisterWithSessionAsync(TIdentity userData, string password)
  {
    if (await _store.EmailExistsAsync(userData.Email))
      return AuthSessionResult<TIdentity>.Failure("Email already registered.");

    userData.PasswordHash = PasswordHelper<TIdentity>.HashPassword(userData, password);
    var user = await _store.CreateAsync(userData);
    return await _refreshTokenService.IssueSessionAsync(user);
  }

  public async Task<AuthResult<TIdentity>> LoginAsync(string email, string password)
  {
    if (!await _abuseProtector.IsLoginAllowedAsync(email))
      return AuthResult<TIdentity>.Failure("Too many failed attempts. Try again later.");

    var user = await _store.FindByEmailAsync(email);
    if (user == null)
    {
      await _abuseProtector.RecordFailedLoginAsync(email);
      return AuthResult<TIdentity>.Failure("Invalid credentials.");
    }

    var result = PasswordHelper<TIdentity>.VerifyPassword(user, user.PasswordHash, password);
    if (result == PasswordVerificationResult.Failed)
    {
      await _abuseProtector.RecordFailedLoginAsync(email);
      return AuthResult<TIdentity>.Failure("Invalid credentials.");
    }

    await _abuseProtector.RecordSuccessfulLoginAsync(email);

    return AuthResult<TIdentity>.Success(user, _jwt.GenerateToken(user));
  }

  public async Task<AuthSessionResult<TIdentity>> LoginWithSessionAsync(string email, string password)
  {
    if (!await _abuseProtector.IsLoginAllowedAsync(email))
      return AuthSessionResult<TIdentity>.Failure("Too many failed attempts. Try again later.");

    var user = await _store.FindByEmailAsync(email);
    if (user == null)
    {
      await _abuseProtector.RecordFailedLoginAsync(email);
      return AuthSessionResult<TIdentity>.Failure("Invalid credentials.");
    }

    var result = PasswordHelper<TIdentity>.VerifyPassword(user, user.PasswordHash, password);
    if (result == PasswordVerificationResult.Failed)
    {
      await _abuseProtector.RecordFailedLoginAsync(email);
      return AuthSessionResult<TIdentity>.Failure("Invalid credentials.");
    }

    await _abuseProtector.RecordSuccessfulLoginAsync(email);
    return await _refreshTokenService.IssueSessionAsync(user);
  }

  public async Task<AuthResult<TIdentity>> ResetPasswordAsync(string email, string newPassword)
  {
    return AuthResult<TIdentity>.Failure("Direct password reset is disabled. Use token-based reset via EmailAuthService.");
  }

  public AuthResult<TIdentity> GenerateAuthToken(TIdentity user)
  {
    if (user == null)
      return AuthResult<TIdentity>.Failure("Invalid credentials.");
    return AuthResult<TIdentity>.Success(user, _jwt.GenerateToken(user));
  }


  public async Task<AuthResult<TIdentity>> RefreshAuthToken(string token, int refreshExtensionInHours = 1)
  {
    var email = _jwt.GetEmailFromToken(token, allowExpired: true);
    if (string.IsNullOrWhiteSpace(email))
      return AuthResult<TIdentity>.Failure("Invalid token.");

    var user = await _store.FindByEmailAsync(email);
    if (user == null)
      return AuthResult<TIdentity>.Failure("Invalid credentials.");

    string result;
    try
    {
      result = _jwt.RefreshToken(token, user, refreshExtensionInHours);
    }
    catch
    {
      return AuthResult<TIdentity>.Failure("Invalid token.");
    }

    if (string.IsNullOrWhiteSpace(result))
      return AuthResult<TIdentity>.Failure("Invalid token.");
    return AuthResult<TIdentity>.Success(user, result);
  }

  public Task<AuthSessionResult<TIdentity>> RotateRefreshTokenAsync(string refreshToken)
  {
    return _refreshTokenService.RotateAsync(refreshToken);
  }

  public Task RevokeRefreshTokenAsync(string refreshToken)
  {
    return _refreshTokenService.RevokeAsync(refreshToken);
  }

}
