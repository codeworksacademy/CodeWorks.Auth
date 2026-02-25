using System.Security.Claims;
using CodeWorks.Auth.Interfaces;

namespace CodeWorks.Auth.Security;

public interface IJwtService
{
  string GenerateToken(IAccountIdentityBase identity);
  ClaimsPrincipal? ValidateToken(string token);
  string RefreshToken(string token, IAccountIdentityBase identity, int expirationWindowInHours = 1);
  string GetEmailFromToken(string token, bool allowExpired = false);
}
