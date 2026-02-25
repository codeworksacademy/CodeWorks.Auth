namespace CodeWorks.Auth.Models;

public class PasskeyCredentialRecord
{
  public string CredentialId { get; set; } = string.Empty;
  public string UserId { get; set; } = string.Empty;
  public string PublicKey { get; set; } = string.Empty;
  public uint SignCount { get; set; }
  public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
  public DateTime? LastUsedAt { get; set; }
}
