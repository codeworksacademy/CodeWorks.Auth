using System.Security.Claims;

namespace CodeWorks.Auth.Models;

public class JwtClaimMap : Dictionary<string, string>
{

  public JwtClaimMap()
  {
    // Default IAccountIdentity properties
    this["Id"] = ClaimTypes.NameIdentifier;
    this["Email"] = ClaimTypes.Email;
    this["Name"] = "name";
    this["Picture"] = "picture";
    this["IsEmailVerified"] = "email_verified";
    this["Roles"] = ClaimTypes.Role;
    this["Permissions"] = "permission";

    // Optional: other default props
    this["Provider"] = "provider";
    this["ProviderId"] = "provider_id";
    this["ProfilePictureUrl"] = "profile_picture_url";
    this["LastLoginAt"] = "last_login_at";
  }


}
