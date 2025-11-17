using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Claims;
using CodeWorks.Auth.Interfaces;
using CodeWorks.Auth.Models;

namespace CodeWorks.Auth.Security;

public static class ClaimsExtensions
{
    // Internal claim map, configured once at startup
    private static JwtClaimMap _claimMap = [];

    /// <summary>
    /// Configure the global claim map once at application startup.
    /// Maps IAccountIdentity properties to JWT claim types.
    /// </summary>
    /// <param name="map"></param>
    public static void Configure(JwtClaimMap map)
    {
        _claimMap = map ?? throw new ArgumentNullException(nameof(map));
    }

    /// <summary>
    /// Get roles from ClaimsPrincipal using claim map
    /// </summary>
    public static IEnumerable<string> GetRoles(this ClaimsPrincipal user)
    {
        var type = _claimMap.TryGetValue("Roles", out var mapped) ? mapped : ClaimTypes.Role;
        return user.FindAll(type).Select(c => c.Value).Distinct();
    }

    /// <summary>
    /// Get permissions from ClaimsPrincipal using claim map
    /// </summary>
    public static IEnumerable<string> GetPermissions(this ClaimsPrincipal user)
    {
        var type = _claimMap.TryGetValue("Permissions", out var mapped) ? mapped : "permission";
        return user.FindAll(type).Select(c => c.Value).Distinct();
    }

    /// <summary>
    /// Convert ClaimsPrincipal to a strongly-typed IAccountIdentity implementation.
    /// Dynamically populates all properties listed in the configured JwtClaimMap.
    /// </summary>
    public static TUser ToUser<TUser>(this ClaimsPrincipal user)
            where TUser : IAccountIdentity, new()
    {
        var instance = new TUser();

        foreach (var kvp in _claimMap)
        {
            var property = typeof(TUser).GetProperty(kvp.Key, BindingFlags.Public | BindingFlags.Instance);
            if (property == null || !property.CanWrite)
                continue;

            var claims = user.Claims.Where(c => c.Type == kvp.Value).ToList();
            if (claims.Count == 0) continue;

            try
            {
                if (property.PropertyType == typeof(string))
                {
                    property.SetValue(instance, claims.First().Value);
                }
                else if (property.PropertyType == typeof(bool))
                {
                    property.SetValue(instance, bool.Parse(claims.First().Value));
                }
                else if (property.PropertyType == typeof(DateTime))
                {
                    property.SetValue(instance, DateTime.Parse(claims.First().Value));
                }
                else if (property.PropertyType == typeof(DateTime?))
                {
                    property.SetValue(instance, DateTime.TryParse(claims.First().Value, out var dt) ? dt : null);
                }
                else if (property.PropertyType == typeof(Guid))
                {
                    property.SetValue(instance, Guid.Parse(claims.First().Value));
                }
                else if (property.PropertyType == typeof(Guid?))
                {
                    property.SetValue(instance, string.IsNullOrWhiteSpace(claims.First().Value) ? (Guid?)null : Guid.Parse(claims.First().Value));
                }
                else if (typeof(IEnumerable<string>).IsAssignableFrom(property.PropertyType))
                {
                    property.SetValue(instance, claims.Select(c => c.Value).Distinct().ToList());
                }
                else
                {
                    // Fallback: attempt Convert.ChangeType
                    var converted = Convert.ChangeType(claims.First().Value, property.PropertyType);
                    property.SetValue(instance, converted);
                }
            }
            catch
            {
                // ignore invalid conversions
            }
        }

        return instance;
    }
}
