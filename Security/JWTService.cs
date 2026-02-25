using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using CodeWorks.Auth.Interfaces;
using CodeWorks.Auth.Models;
using Microsoft.IdentityModel.Tokens;

namespace CodeWorks.Auth.Security;

public class JwtService(JwtOptions options, JwtClaimMap claimMap) : IJwtService
{
  private readonly JwtOptions _options = options;
  private readonly JwtClaimMap _claimMap = claimMap;

  private TokenValidationParameters BuildValidationParameters(bool validateLifetime)
  {
    return new TokenValidationParameters
    {
      ValidateIssuer = true,
      ValidateAudience = true,
      ValidateLifetime = validateLifetime,
      ValidateIssuerSigningKey = true,
      ValidIssuer = _options.Issuer,
      ValidAudience = _options.Audience,
      IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_options.SigningKey)),
      ClockSkew = TimeSpan.FromMinutes(2),
      RoleClaimType = ClaimTypes.Role,
      NameClaimType = ClaimTypes.Email
    };
  }

  private ClaimsPrincipal? ValidateTokenInternal(string token, bool validateLifetime, out SecurityToken? validatedToken)
  {
    validatedToken = null;
    var tokenHandler = new JwtSecurityTokenHandler();

    try
    {
      var principal = tokenHandler.ValidateToken(token, BuildValidationParameters(validateLifetime), out var securityToken);

      if (securityToken is not JwtSecurityToken jwtToken ||
          !string.Equals(jwtToken.Header.Alg, SecurityAlgorithms.HmacSha256, StringComparison.OrdinalIgnoreCase))
      {
        return null;
      }

      validatedToken = securityToken;
      return principal;
    }
    catch
    {
      return null;
    }
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
    return ValidateTokenInternal(token, validateLifetime: true, out _);
  }

  public string RefreshToken(string staleToken, IAccountIdentity user, int expirationWindowInHours = 5)
  {
    if (user == null) throw new ArgumentNullException(nameof(user));

    var principal = ValidateTokenInternal(staleToken, validateLifetime: false, out var validatedToken);
    if (principal == null || validatedToken is not JwtSecurityToken jwtToken)
      throw new SecurityTokenException("Invalid token.");

    var tokenEmail = principal.FindFirstValue(ClaimTypes.Email) ?? principal.FindFirstValue("email");
    if (string.IsNullOrWhiteSpace(tokenEmail) ||
        !string.Equals(tokenEmail, user.Email, StringComparison.OrdinalIgnoreCase))
    {
      throw new SecurityTokenException("Token subject does not match user.");
    }

    var refreshWindow = jwtToken.ValidTo + TimeSpan.FromHours(expirationWindowInHours);
    if (refreshWindow < DateTime.UtcNow)
      throw new SecurityTokenExpiredException("Token is expired. Cannot refresh.");

    return GenerateToken(user);
  }

  public string GetEmailFromToken(string token, bool allowExpired = false)
  {
    var principal = ValidateTokenInternal(token, validateLifetime: !allowExpired, out _);
    if (principal == null) return string.Empty;
    return principal.FindFirstValue(ClaimTypes.Email) ?? principal.FindFirstValue("email") ?? string.Empty;
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
