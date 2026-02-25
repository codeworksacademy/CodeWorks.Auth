using CodeWorks.Auth.Interfaces;
using CodeWorks.Auth.Models;

namespace CodeWorks.Auth.Services;

public class NoOpPasskeyResponseVerifier : IPasskeyResponseVerifier
{
  public Task<PasskeyRegistrationValidationResult> VerifyRegistrationAsync(
      string attestationResponseJson,
      string expectedChallenge,
      string expectedUserId,
      PasskeyOptions options)
  {
    return Task.FromResult(PasskeyRegistrationValidationResult.Failure());
  }

  public Task<PasskeyAuthenticationValidationResult> VerifyAuthenticationAsync(
      string assertionResponseJson,
      string expectedChallenge,
      PasskeyCredentialRecord credential,
      PasskeyOptions options)
  {
    return Task.FromResult(PasskeyAuthenticationValidationResult.Failure());
  }
}
