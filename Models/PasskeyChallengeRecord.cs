namespace CodeWorks.Auth.Models;

public class PasskeyChallengeRecord
{
  public string Challenge { get; set; } = string.Empty;
  public string? UserId { get; set; }
  public PasskeyChallengePurpose Purpose { get; set; }
  public DateTime ExpiresAt { get; set; }
  public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
