using System.Security.Claims;
using CWAuth.Interfaces;

namespace CWAuth.Security;

public interface IJwtService
{
  string GenerateToken(IAccountIdentity identity);
  ClaimsPrincipal? ValidateToken(string token);
}
