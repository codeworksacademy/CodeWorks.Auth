using CodeWorks.Auth.Models;

namespace CodeWorks.Auth.Interfaces;

public interface IRefreshTokenStore
{
  Task SaveTokenAsync(RefreshTokenRecord token);
  Task<RefreshTokenRecord?> GetTokenAsync(string tokenHash);
  Task RevokeTokenAsync(string tokenHash, string? replacedByTokenHash = null);
}
