using System.Security.Claims;

namespace CWAuth.Security;

public static class ClaimsExtensions
{
    public static IEnumerable<string> GetPermissions(this ClaimsPrincipal user) =>
        user.Claims.Where(c => c.Type == "permission").Select(c => c.Value);

    public static IEnumerable<string> GetRoles(this ClaimsPrincipal user) =>
        user.Claims.Where(c => c.Type == ClaimTypes.Role).Select(c => c.Value);
}
