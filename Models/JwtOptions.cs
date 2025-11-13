using CodeWorks.Auth.Models;

public class JwtOptions
{
    public string SigningKey { get; set; } = null!;
    public string Issuer { get; set; } = "default-issuer";
    public string Audience { get; set; } = "default-audience";
    public TimeSpan Expiration { get; set; } = TimeSpan.FromHours(1);
    public string CookieName { get; set; } = "access-token";
    public JwtClaimMap ClaimMap { get; } = [];

}
