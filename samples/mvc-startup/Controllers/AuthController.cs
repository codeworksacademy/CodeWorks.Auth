using CodeWorks.Auth.Interfaces;
using CodeWorks.Auth.MvcSample.Models;
using Microsoft.AspNetCore.Mvc;

namespace CodeWorks.Auth.MvcSample.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
  private readonly IAuthService<AppUser> _auth;

  public AuthController(IAuthService<AppUser> auth)
  {
    _auth = auth;
  }

  [HttpPost("register")]
  public async Task<IActionResult> Register([FromBody] RegisterRequest request)
  {
    var normalizedEmail = request.Email.Trim().ToLowerInvariant();

    var user = new AppUser
    {
      Email = normalizedEmail,
      Name = string.IsNullOrWhiteSpace(request.Name) ? request.Email.Split('@')[0] : request.Name.Trim(),
      IsEmailVerified = true
    };

    var result = await _auth.RegisterWithSessionAsync(user, request.Password);
    if (!result.IsSuccessful)
    {
      var loginFallback = await _auth.LoginWithSessionAsync(normalizedEmail, request.Password);
      if (!loginFallback.IsSuccessful)
        return BadRequest(new { error = result.Error });

      result = loginFallback;
    }

    return Ok(new
    {
      accessToken = result.AccessToken,
      refreshToken = result.RefreshToken,
      expiresAt = result.RefreshTokenExpiresAt,
      user = new { result.User!.Id, result.User.Email, result.User.Name }
    });
  }

  [HttpPost("login")]
  public async Task<IActionResult> Login([FromBody] LoginRequest request)
  {
    var result = await _auth.LoginWithSessionAsync(request.Email.Trim().ToLowerInvariant(), request.Password);
    if (!result.IsSuccessful) return Unauthorized(new { error = result.Error });

    return Ok(new
    {
      accessToken = result.AccessToken,
      refreshToken = result.RefreshToken,
      expiresAt = result.RefreshTokenExpiresAt,
      user = new { result.User!.Id, result.User.Email, result.User.Name }
    });
  }

  [HttpPost("refresh")]
  public async Task<IActionResult> Refresh([FromBody] RefreshRequest request)
  {
    var result = await _auth.RotateRefreshTokenAsync(request.RefreshToken);
    if (!result.IsSuccessful) return Unauthorized(new { error = result.Error });

    return Ok(new
    {
      accessToken = result.AccessToken,
      refreshToken = result.RefreshToken,
      expiresAt = result.RefreshTokenExpiresAt
    });
  }
}
