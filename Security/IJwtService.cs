using System.Security.Claims;
using CodeWorks.Auth.Interfaces;

namespace CodeWorks.Auth.Security;

public interface IJwtService
{
  string GenerateToken(IAccountIdentity identity);
  ClaimsPrincipal? ValidateToken(string token);
  string RefreshToken(string token, IAccountIdentity identity, int expirationWindowInHours = 1);
  string GetEmailFromToken(string token, bool allowExpired = false);
}
