using CodeWorks.Auth.Models;

namespace CodeWorks.Auth.Interfaces;

public interface IRefreshTokenService<TIdentity> where TIdentity : IAccountIdentityBase
{
  Task<AuthSessionResult<TIdentity>> IssueSessionAsync(TIdentity user);
  Task<AuthSessionResult<TIdentity>> RotateAsync(string refreshToken);
  Task RevokeAsync(string refreshToken);
}
