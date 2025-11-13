using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using CodeWorks.Auth.Interfaces;
using CodeWorks.Auth.Models;
using Microsoft.IdentityModel.Tokens;

namespace CodeWorks.Auth.Security;

public class JwtService : IJwtService
{
  private readonly JwtOptions _options;
  private readonly JwtClaimMap _claimMap;

  public JwtService(JwtOptions options, JwtClaimMap claimMap)
  {
    _options = options;
    _claimMap = claimMap;
  }

  public string GenerateToken(IAccountIdentity user)
  {
    if (user == null) throw new ArgumentNullException(nameof(user));

    // --- Step 1: Ensure fallback values for Name & Picture ---
    if (string.IsNullOrWhiteSpace(user.Name) && !string.IsNullOrWhiteSpace(user.Email))
      user.Name = user.Email[..user.Email.IndexOf('@')];

    if (string.IsNullOrWhiteSpace(user.Picture) && !string.IsNullOrWhiteSpace(user.Email))
      user.Picture = $"https://ui-avatars.com/api/?name={user.Name}&color=fff&background={StringToHex(user.Email)}";

    // --- Step 2: Map all properties in claim map ---
    var claims = new List<Claim>();

    foreach (var kvp in _claimMap)
    {
      var property = user.GetType().GetProperty(kvp.Key);
      if (property == null) continue;

      var value = property.GetValue(user);
      if (value == null) continue;

      switch (value)
      {
        case IEnumerable<string> list when kvp.Value != ClaimTypes.Email:
          var items = list.Where(v => !string.IsNullOrWhiteSpace(v)).ToList();
          if (items.Count > 0)
            claims.AddRange(items.Select(v => new Claim(kvp.Value, v)));
          break;

        case bool b:
          claims.Add(new Claim(kvp.Value, b.ToString()));
          break;

        case DateTime dt:
          claims.Add(new Claim(kvp.Value, dt.ToString("o"))); // ISO 8601
          break;

        default:
          claims.Add(new Claim(kvp.Value, value.ToString()!));
          break;
      }
    }

    // --- Step 3: Standard JWT claims ---
    claims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));
    claims.Add(new Claim("iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64));

    // --- Step 4: Create token ---
    var token = new JwtSecurityToken(
        issuer: _options.Issuer,
        audience: _options.Audience,
        claims: claims,
        expires: DateTime.UtcNow.Add(_options.Expiration),
        signingCredentials: new SigningCredentials(
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_options.SigningKey)),
            SecurityAlgorithms.HmacSha256)
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


  public static string StringToHex(string str = "")
  {
    try
    {
      if (string.IsNullOrEmpty(str)) return string.Empty;
      if (str.Length > 6) str = str[..6];
      return string.Join("", str.Select(c => ((int)c).ToString("x2")))[..6];
    }
    catch (Exception e)
    {
      Console.WriteLine(e.Message);
      return string.Empty;
    }
  }


}
