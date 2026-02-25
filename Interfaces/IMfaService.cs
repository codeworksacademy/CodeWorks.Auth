using CodeWorks.Auth.Models;

namespace CodeWorks.Auth.Interfaces;

public interface IMfaService<TIdentity> where TIdentity : IAccountIdentity
{
  Task<MfaEnrollmentResult> BeginAuthenticatorEnrollmentAsync(TIdentity user, string issuer);
  Task<bool> EnableAuthenticatorAsync(TIdentity user, string code);
  Task<bool> VerifyAuthenticatorCodeAsync(TIdentity user, string code);
  Task<bool> IsAuthenticatorEnabledAsync(TIdentity user);
  Task<IReadOnlyList<string>> GenerateRecoveryCodesAsync(TIdentity user, int count = 10);
  Task<bool> RedeemRecoveryCodeAsync(TIdentity user, string recoveryCode);
}
