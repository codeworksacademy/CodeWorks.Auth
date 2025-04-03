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

  public string GenerateToken(IAccountIdentity accountIdentity)
  {
    var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, accountIdentity.Id),
            new(ClaimTypes.Email, accountIdentity.Email)
        };

    claims.AddRange(accountIdentity.Roles.Select(role => new Claim(ClaimTypes.Role, role)));
    claims.AddRange(accountIdentity.Permissions.Select(p => new Claim("permission", p)));

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
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_options.SigningKey)),
        ValidateIssuer = true,
        ValidIssuer = _options.Issuer,
        ValidateAudience = true,
        ValidAudience = _options.Audience,
        ValidateLifetime = true,
        ClockSkew = TimeSpan.Zero
      }, out _);
    }
    catch
    {
      return null;
    }
  }
}
