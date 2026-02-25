using CodeWorks.Auth.Models;

namespace CodeWorks.Auth.Interfaces;

public interface IPasskeyResponseVerifier
{
  Task<PasskeyRegistrationValidationResult> VerifyRegistrationAsync(
      string attestationResponseJson,
      string expectedChallenge,
      string expectedUserId,
      PasskeyOptions options);

  Task<PasskeyAuthenticationValidationResult> VerifyAuthenticationAsync(
      string assertionResponseJson,
      string expectedChallenge,
      PasskeyCredentialRecord credential,
      PasskeyOptions options);
}
