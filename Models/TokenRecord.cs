public class TokenRecord
{
    public string Token { get; set; } = null!;
    public string UserId { get; set; } = null!;
    public EmailTokenPurpose Purpose { get; set; }
    public DateTime ExpiresAt { get; set; }
    public bool Used { get; set; } = false;
}
