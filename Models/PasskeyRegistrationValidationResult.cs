namespace CodeWorks.Auth.Models;

public class PasskeyRegistrationValidationResult
{
  public bool IsValid { get; init; }
  public string? CredentialId { get; init; }
  public string? PublicKey { get; init; }
  public uint SignCount { get; init; }

  public static PasskeyRegistrationValidationResult Success(string credentialId, string publicKey, uint signCount)
      => new() { IsValid = true, CredentialId = credentialId, PublicKey = publicKey, SignCount = signCount };

  public static PasskeyRegistrationValidationResult Failure()
      => new() { IsValid = false };
}
