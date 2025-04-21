using Microsoft.AspNetCore.Authorization;

namespace CodeWorks.Auth.Security;

public class PermissionRequirement(string permission) : IAuthorizationRequirement
{
  public string Permission { get; } = permission;
}
