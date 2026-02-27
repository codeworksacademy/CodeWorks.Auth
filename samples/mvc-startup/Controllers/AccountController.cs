using CodeWorks.Auth.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CodeWorks.Auth.MvcSample.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class AccountController : ControllerBase
{
  [HttpGet("me")]
  public IActionResult Me()
  {
    var email = User.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value ?? User.Identity?.Name;
    var roles = User.GetRoles().ToArray();
    var permissions = User.GetPermissions().ToArray();

    return Ok(new
    {
      email,
      roles,
      permissions,
      claims = User.Claims.Select(c => new { c.Type, c.Value })
    });
  }
}
