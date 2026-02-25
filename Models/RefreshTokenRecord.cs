namespace CodeWorks.Auth.Models;

public class RefreshTokenRecord
{
  public string TokenHash { get; set; } = string.Empty;
  public string UserId { get; set; } = string.Empty;
  public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
  public DateTime ExpiresAt { get; set; }
  public DateTime? RevokedAt { get; set; }
  public string? ReplacedByTokenHash { get; set; }

  public bool IsActive => RevokedAt == null && ExpiresAt > DateTime.UtcNow;
}
