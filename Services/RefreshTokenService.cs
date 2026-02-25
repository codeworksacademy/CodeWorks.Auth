using CodeWorks.Auth.Interfaces;
using CodeWorks.Auth.Models;
using CodeWorks.Auth.Security;

namespace CodeWorks.Auth.Services;

public class RefreshTokenService<TIdentity> : IRefreshTokenService<TIdentity>
    where TIdentity : class, IAccountIdentity
{
  private readonly IAccountIdentityStore<TIdentity> _store;
  private readonly IJwtService _jwt;
  private readonly IRefreshTokenStore _refreshTokenStore;
  private readonly JwtOptions _jwtOptions;

  public RefreshTokenService(
      IAccountIdentityStore<TIdentity> store,
      IJwtService jwt,
      IRefreshTokenStore refreshTokenStore,
      JwtOptions jwtOptions)
  {
    _store = store;
    _jwt = jwt;
    _refreshTokenStore = refreshTokenStore;
    _jwtOptions = jwtOptions;
  }

  public async Task<AuthSessionResult<TIdentity>> IssueSessionAsync(TIdentity user)
  {
    var accessToken = _jwt.GenerateToken(user);
    var refreshToken = TokenHelper.GenerateToken(64);
    var refreshTokenHash = TokenHelper.HashToken(refreshToken);
    var refreshTokenExpiresAt = DateTime.UtcNow.Add(_jwtOptions.RefreshTokenExpiration);

    await _refreshTokenStore.SaveTokenAsync(new RefreshTokenRecord
    {
      TokenHash = refreshTokenHash,
      UserId = user.Id,
      CreatedAt = DateTime.UtcNow,
      ExpiresAt = refreshTokenExpiresAt
    });

    return AuthSessionResult<TIdentity>.Success(user, accessToken, refreshToken, refreshTokenExpiresAt);
  }

  public async Task<AuthSessionResult<TIdentity>> RotateAsync(string refreshToken)
  {
    var refreshTokenHash = TokenHelper.HashToken(refreshToken);
    var currentRecord = await _refreshTokenStore.TryConsumeActiveTokenAsync(refreshTokenHash);

    if (currentRecord == null)
      return AuthSessionResult<TIdentity>.Failure("Invalid refresh token.");

    var user = await _store.FindByIdAsync(currentRecord.UserId);
    if (user == null)
      return AuthSessionResult<TIdentity>.Failure("Invalid refresh token.");

    var newRefreshToken = TokenHelper.GenerateToken(64);
    var newRefreshTokenHash = TokenHelper.HashToken(newRefreshToken);
    var newRefreshTokenExpiresAt = DateTime.UtcNow.Add(_jwtOptions.RefreshTokenExpiration);

    await _refreshTokenStore.SaveTokenAsync(new RefreshTokenRecord
    {
      TokenHash = newRefreshTokenHash,
      UserId = user.Id,
      CreatedAt = DateTime.UtcNow,
      ExpiresAt = newRefreshTokenExpiresAt
    });

    await _refreshTokenStore.RevokeTokenAsync(refreshTokenHash, newRefreshTokenHash);

    var newAccessToken = _jwt.GenerateToken(user);
    return AuthSessionResult<TIdentity>.Success(user, newAccessToken, newRefreshToken, newRefreshTokenExpiresAt);
  }

  public async Task RevokeAsync(string refreshToken)
  {
    var refreshTokenHash = TokenHelper.HashToken(refreshToken);
    await _refreshTokenStore.RevokeTokenAsync(refreshTokenHash);
  }
}
