using Microsoft.AspNetCore.Authorization;

namespace CWAuth.Security;

public class HasPermissionAttribute : AuthorizeAttribute
{
    public HasPermissionAttribute(string permission)
    {
        Policy = permission;
    }
}