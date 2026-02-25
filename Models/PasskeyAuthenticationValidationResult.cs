namespace CodeWorks.Auth.Models;

public class PasskeyAuthenticationValidationResult
{
  public bool IsValid { get; init; }
  public uint NewSignCount { get; init; }

  public static PasskeyAuthenticationValidationResult Success(uint newSignCount)
      => new() { IsValid = true, NewSignCount = newSignCount };

  public static PasskeyAuthenticationValidationResult Failure()
      => new() { IsValid = false };
}
