namespace CodeWorks.Auth.Models;

public class PasskeyOptions
{
  public string RpId { get; set; } = "localhost";
  public string RpName { get; set; } = "CodeWorks";
  public string ExpectedOrigin { get; set; } = "https://localhost";
  public TimeSpan ChallengeLifetime { get; set; } = TimeSpan.FromMinutes(5);
  public int TimeoutMs { get; set; } = 60000;
}
