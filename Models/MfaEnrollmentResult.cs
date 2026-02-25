namespace CodeWorks.Auth.Models;

public class MfaEnrollmentResult
{
  public string ManualEntryKey { get; set; } = string.Empty;
  public string AuthenticatorUri { get; set; } = string.Empty;
}
