using System.Security.Claims;
using CodeWorks.Auth.Interfaces;

namespace CodeWorks.Auth.Security;

public static class ClaimsExtensions
{
    public static IEnumerable<string> GetPermissions(this ClaimsPrincipal user) =>
        user.Claims.Where(c => c.Type == "permission").Select(c => c.Value);

    public static IEnumerable<string> GetRoles(this ClaimsPrincipal user) =>
        user.Claims.Where(c => c.Type == ClaimTypes.Role).Select(c => c.Value);

    public static TUser ToUser<TUser>(this ClaimsPrincipal user) where TUser : IAccountIdentity, new()
    {
        return new TUser
        {
            Id = user.FindFirst("id")?.Value ?? user.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "",
            Email = user.FindFirst("email")?.Value ?? user.FindFirst(ClaimTypes.Email)?.Value ?? "",
            Name = user.FindFirst("name")?.Value ?? user.FindFirst(ClaimTypes.Email)?.Value ?? "",
            Picture = user.FindFirst("picture")?.Value ?? "",
            IsEmailVerified = user.FindFirst("email_verified")?.Value == "true",
            Roles = user.FindAll(ClaimTypes.Role).Select(c => c.Value).Distinct().ToList(),
            Permissions = user.FindAll("permission").Select(c => c.Value).Distinct().ToList(),
        };
    }

}
