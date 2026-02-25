using System.Text.Json;
using CodeWorks.Auth.Interfaces;
using CodeWorks.Auth.Models;
using CodeWorks.Auth.Security;

namespace CodeWorks.Auth.Services;

public class PasskeyService<TIdentity> : IPasskeyService<TIdentity> where TIdentity : class, IAccountIdentityBase
{
  private readonly IAccountIdentityStore<TIdentity> _identityStore;
  private readonly IPasskeyChallengeStore _challengeStore;
  private readonly IPasskeyCredentialStore _credentialStore;
  private readonly IPasskeyResponseVerifier _responseVerifier;
  private readonly PasskeyOptions _options;

  public PasskeyService(
      IAccountIdentityStore<TIdentity> identityStore,
      IPasskeyChallengeStore challengeStore,
      IPasskeyCredentialStore credentialStore,
      IPasskeyResponseVerifier responseVerifier,
      PasskeyOptions options)
  {
    _identityStore = identityStore;
    _challengeStore = challengeStore;
    _credentialStore = credentialStore;
    _responseVerifier = responseVerifier;
    _options = options;
  }

  public async Task<PasskeyOperationResult> BeginRegistrationAsync(TIdentity user)
  {
    var challenge = TokenHelper.GenerateToken(32);
    await _challengeStore.SaveAsync(new PasskeyChallengeRecord
    {
      Challenge = challenge,
      UserId = user.IdAsString,
      Purpose = PasskeyChallengePurpose.Registration,
      ExpiresAt = DateTime.UtcNow.Add(_options.ChallengeLifetime)
    });

    var existingCredentials = await _credentialStore.GetByUserIdAsync(user.IdAsString);

    var optionsPayload = new
    {
      challenge,
      rp = new { id = _options.RpId, name = _options.RpName },
      user = new { id = user.IdAsString, name = user.Email, displayName = user.Name },
      pubKeyCredParams = new[]
      {
        new { type = "public-key", alg = -7 },
        new { type = "public-key", alg = -257 }
      },
      timeout = _options.TimeoutMs,
      attestation = "none",
      authenticatorSelection = new
      {
        residentKey = "preferred",
        userVerification = "preferred"
      },
      excludeCredentials = existingCredentials.Select(x => new { id = x.CredentialId, type = "public-key" })
    };

    var optionsJson = JsonSerializer.Serialize(optionsPayload);
    return PasskeyOperationResult.Success(optionsJson);
  }

  public async Task<bool> CompleteRegistrationAsync(TIdentity user, string attestationResponseJson)
  {
    var challenge = ExtractChallenge(attestationResponseJson);
    if (string.IsNullOrWhiteSpace(challenge))
      return false;

    var challengeRecord = await _challengeStore.ConsumeAsync(
        challenge,
        PasskeyChallengePurpose.Registration,
        user.IdAsString);
    if (challengeRecord == null)
      return false;

    var validation = await _responseVerifier.VerifyRegistrationAsync(
        attestationResponseJson,
        challenge,
        user.IdAsString,
        _options);

    if (!validation.IsValid ||
        string.IsNullOrWhiteSpace(validation.CredentialId) ||
        string.IsNullOrWhiteSpace(validation.PublicKey))
    {
      return false;
    }

    await _credentialStore.SaveAsync(new PasskeyCredentialRecord
    {
      CredentialId = validation.CredentialId,
      PublicKey = validation.PublicKey,
      UserId = user.IdAsString,
      SignCount = validation.SignCount,
      CreatedAt = DateTime.UtcNow
    });

    return true;
  }

  public async Task<PasskeyOperationResult> BeginAuthenticationAsync(string? userId = null)
  {
    var challenge = TokenHelper.GenerateToken(32);

    await _challengeStore.SaveAsync(new PasskeyChallengeRecord
    {
      Challenge = challenge,
      UserId = userId,
      Purpose = PasskeyChallengePurpose.Authentication,
      ExpiresAt = DateTime.UtcNow.Add(_options.ChallengeLifetime)
    });

    IReadOnlyList<PasskeyCredentialRecord> credentials = [];
    if (!string.IsNullOrWhiteSpace(userId))
      credentials = await _credentialStore.GetByUserIdAsync(userId);

    var optionsPayload = new
    {
      challenge,
      timeout = _options.TimeoutMs,
      rpId = _options.RpId,
      userVerification = "preferred",
      allowCredentials = credentials.Select(x => new { id = x.CredentialId, type = "public-key" })
    };

    var optionsJson = JsonSerializer.Serialize(optionsPayload);
    return PasskeyOperationResult.Success(optionsJson);
  }

  public async Task<TIdentity?> CompleteAuthenticationAsync(string assertionResponseJson)
  {
    var challenge = ExtractChallenge(assertionResponseJson);
    var credentialId = ExtractCredentialId(assertionResponseJson);

    if (string.IsNullOrWhiteSpace(challenge) || string.IsNullOrWhiteSpace(credentialId))
      return null;

    var challengeRecord = await _challengeStore.ConsumeAsync(
      challenge,
      PasskeyChallengePurpose.Authentication);
    if (challengeRecord == null)
      return null;

    var credential = await _credentialStore.GetAsync(credentialId);
    if (credential == null)
      return null;

    if (!string.IsNullOrWhiteSpace(challengeRecord!.UserId) &&
        !string.Equals(challengeRecord.UserId, credential.UserId, StringComparison.Ordinal))
    {
      return null;
    }

    var validation = await _responseVerifier.VerifyAuthenticationAsync(
        assertionResponseJson,
        challenge,
        credential,
        _options);

    if (!validation.IsValid)
      return null;

    await _credentialStore.UpdateUsageAsync(credentialId, validation.NewSignCount, DateTime.UtcNow);
    return await _identityStore.FindByIdAsync(credential.UserId);
  }

  private static string? ExtractChallenge(string responseJson)
  {
    try
    {
      using var document = JsonDocument.Parse(responseJson);
      if (document.RootElement.TryGetProperty("challenge", out var challengeElement) &&
          challengeElement.ValueKind == JsonValueKind.String)
      {
        return challengeElement.GetString();
      }

      return null;
    }
    catch
    {
      return null;
    }
  }

  private static string? ExtractCredentialId(string responseJson)
  {
    try
    {
      using var document = JsonDocument.Parse(responseJson);
      if (document.RootElement.TryGetProperty("credentialId", out var credentialIdElement) &&
          credentialIdElement.ValueKind == JsonValueKind.String)
      {
        return credentialIdElement.GetString();
      }

      if (document.RootElement.TryGetProperty("id", out var idElement) &&
          idElement.ValueKind == JsonValueKind.String)
      {
        return idElement.GetString();
      }

      return null;
    }
    catch
    {
      return null;
    }
  }
}
