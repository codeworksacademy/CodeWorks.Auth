using CodeWorks.Auth.Models;

namespace CodeWorks.Auth.Interfaces;

public interface IPasskeyService<TIdentity> where TIdentity : IAccountIdentityBase
{
  Task<PasskeyOperationResult> BeginRegistrationAsync(TIdentity user);
  Task<bool> CompleteRegistrationAsync(TIdentity user, string attestationResponseJson);
  Task<PasskeyOperationResult> BeginAuthenticationAsync(string? userId = null);
  Task<TIdentity?> CompleteAuthenticationAsync(string assertionResponseJson);
}
