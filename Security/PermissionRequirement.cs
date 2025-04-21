using Microsoft.AspNetCore.Authorization;

namespace CWAuth.Security;

public class PermissionRequirement(string permission) : IAuthorizationRequirement
{
  public string Permission { get; } = permission;
}
