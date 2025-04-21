using Microsoft.AspNetCore.Authorization;

namespace CodeWorks.Auth.Security;

public class HasPermissionAttribute : AuthorizeAttribute
{
    public HasPermissionAttribute(string permission)
    {
        Policy = permission;
    }
}