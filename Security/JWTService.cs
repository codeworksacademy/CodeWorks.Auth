using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using CWAuth.Interfaces;
using Microsoft.IdentityModel.Tokens;

namespace CWAuth.Security;

public class JwtService : IJwtService
{
  private readonly JwtOptions _options;

  public JwtService(JwtOptions options)
  {
    _options = options;
  }

  public string GenerateToken(IAccountIdentity user)
  {
    var claims = new List<Claim>
    {
      new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
      new Claim(ClaimTypes.Email, user.Email),
    };

    var roles = user.Roles?.ToArray() ?? Array.Empty<string>();
    claims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)).ToList());


    var permissions = user.Permissions?.ToArray() ?? Array.Empty<string>();
    claims.AddRange(permissions.Select(p => new Claim("permission", p)).ToList());

    if (!string.IsNullOrEmpty(user.Name))
      claims.Add(new Claim("name", user.Name));
    if (!string.IsNullOrEmpty(user.Picture))
      claims.Add(new Claim("picture", user.Picture));

    claims.Add(new Claim("email_verified", user.IsEmailVerified.ToString()));

    var unixTime = new DateTimeOffset(DateTime.UtcNow).ToUnixTimeSeconds();
    claims.Add(new Claim("iat", unixTime.ToString(), ClaimValueTypes.Integer64));

    var token = new JwtSecurityToken(
        issuer: _options.Issuer,
        audience: _options.Audience,
        claims: claims,
        expires: DateTime.UtcNow.Add(_options.Expiration),
        signingCredentials: new SigningCredentials(
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_options.SigningKey)),
            SecurityAlgorithms.HmacSha256
        )
    );

    return new JwtSecurityTokenHandler().WriteToken(token);
  }

  public ClaimsPrincipal? ValidateToken(string token)
  {
    var tokenHandler = new JwtSecurityTokenHandler();
    try
    {
      return tokenHandler.ValidateToken(token, new TokenValidationParameters
      {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = _options.Issuer,
        ValidAudience = _options.Audience,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_options.SigningKey)),
        ClockSkew = TimeSpan.Zero,

        RoleClaimType = ClaimTypes.Role,
        NameClaimType = ClaimTypes.Email

      }, out _);
    }
    catch
    {
      return null;
    }
  }

  public string RefreshToken(string staleToken, IAccountIdentity user, int expirationWindowInHours = 5)
  {
    var tokenHandler = new JwtSecurityTokenHandler();
    var token = tokenHandler.ReadJwtToken(staleToken);

    var refreshWindow = token.ValidTo + TimeSpan.FromHours(expirationWindowInHours);
    var now = DateTime.UtcNow;

    // Check if the token can be refreshed
    if (refreshWindow < now)
      throw new SecurityTokenExpiredException("Token is expired. Cannot refresh.");

    return GenerateToken(user);
  }

  public string GetEmailFromToken(string token)
  {
    var tokenHandler = new JwtSecurityTokenHandler();
    var jwtToken = tokenHandler.ReadJwtToken(token);
    var emailClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email || c.Type == "email");
    return emailClaim?.Value ?? string.Empty;
  }
}
