namespace CodeWorks.Auth.Models;

/// <summary>
/// OAuth state data model for CSRF protection
/// </summary>

public class OAuthState
{
  public string Token { get; set; } = string.Empty;
  public string Provider { get; set; } = string.Empty;
  public string? ReturnUrl { get; set; }
  public DateTime CreatedAt { get; set; }
  public DateTime ExpiresAt { get; set; }
  public bool IsUsed { get; set; }
}