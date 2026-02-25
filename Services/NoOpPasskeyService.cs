using CodeWorks.Auth.Interfaces;
using CodeWorks.Auth.Models;

namespace CodeWorks.Auth.Services;

public class NoOpPasskeyService<TIdentity> : IPasskeyService<TIdentity> where TIdentity : class, IAccountIdentity
{
  public Task<PasskeyOperationResult> BeginRegistrationAsync(TIdentity user)
      => Task.FromResult(PasskeyOperationResult.Failure("Passkey provider not configured."));

  public Task<bool> CompleteRegistrationAsync(TIdentity user, string attestationResponseJson)
      => Task.FromResult(false);

  public Task<PasskeyOperationResult> BeginAuthenticationAsync(string? userId = null)
      => Task.FromResult(PasskeyOperationResult.Failure("Passkey provider not configured."));

  public Task<TIdentity?> CompleteAuthenticationAsync(string assertionResponseJson)
      => Task.FromResult<TIdentity?>(null);
}
