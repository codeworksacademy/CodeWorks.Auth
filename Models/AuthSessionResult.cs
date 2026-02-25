namespace CodeWorks.Auth.Models;

public class AuthSessionResult<TIdentity>
{
  public bool IsSuccessful { get; init; }
  public TIdentity? User { get; init; }
  public string? AccessToken { get; init; }
  public string? RefreshToken { get; init; }
  public DateTime? RefreshTokenExpiresAt { get; init; }
  public string? Error { get; init; }

  public static AuthSessionResult<TIdentity> Success(
      TIdentity user,
      string accessToken,
      string refreshToken,
      DateTime refreshTokenExpiresAt) =>
      new()
      {
        IsSuccessful = true,
        User = user,
        AccessToken = accessToken,
        RefreshToken = refreshToken,
        RefreshTokenExpiresAt = refreshTokenExpiresAt
      };

  public static AuthSessionResult<TIdentity> Failure(string message) =>
      new() { IsSuccessful = false, Error = message };
}
