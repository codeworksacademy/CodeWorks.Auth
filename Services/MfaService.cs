using CodeWorks.Auth.Interfaces;
using CodeWorks.Auth.Models;
using CodeWorks.Auth.Security;

namespace CodeWorks.Auth.Services;

public class MfaService<TIdentity> : IMfaService<TIdentity> where TIdentity : class, IAccountIdentityBase
{
  private readonly IUserMfaStore _mfaStore;

  public MfaService(IUserMfaStore mfaStore)
  {
    _mfaStore = mfaStore;
  }

  public async Task<MfaEnrollmentResult> BeginAuthenticatorEnrollmentAsync(TIdentity user, string issuer)
  {
    var secret = TotpHelper.GenerateSecret();
    await _mfaStore.SetTotpSecretAsync(user.IdAsString, secret);
    await _mfaStore.SetTotpEnabledAsync(user.IdAsString, false);

    return new MfaEnrollmentResult
    {
      ManualEntryKey = secret,
      AuthenticatorUri = TotpHelper.BuildAuthenticatorUri(issuer, user.Email, secret)
    };
  }

  public async Task<bool> EnableAuthenticatorAsync(TIdentity user, string code)
  {
    var secret = await _mfaStore.GetTotpSecretAsync(user.IdAsString);
    if (string.IsNullOrWhiteSpace(secret)) return false;

    var valid = TotpHelper.VerifyCode(secret, code);
    if (!valid) return false;

    await _mfaStore.SetTotpEnabledAsync(user.IdAsString, true);
    return true;
  }

  public async Task<bool> VerifyAuthenticatorCodeAsync(TIdentity user, string code)
  {
    var isEnabled = await _mfaStore.IsTotpEnabledAsync(user.IdAsString);
    if (!isEnabled) return false;

    var secret = await _mfaStore.GetTotpSecretAsync(user.IdAsString);
    if (string.IsNullOrWhiteSpace(secret)) return false;

    return TotpHelper.VerifyCode(secret, code);
  }

  public Task<bool> IsAuthenticatorEnabledAsync(TIdentity user)
  {
    return _mfaStore.IsTotpEnabledAsync(user.IdAsString);
  }

  public async Task<IReadOnlyList<string>> GenerateRecoveryCodesAsync(TIdentity user, int count = 10)
  {
    var normalizedCount = Math.Clamp(count, 1, 50);
    var rawCodes = Enumerable.Range(0, normalizedCount)
        .Select(_ => TokenHelper.GenerateToken(12)[..10].ToUpperInvariant())
        .ToList();

    var hashes = rawCodes.Select(TokenHelper.HashToken);
    await _mfaStore.SaveRecoveryCodeHashesAsync(user.IdAsString, hashes);

    return rawCodes;
  }

  public async Task<bool> RedeemRecoveryCodeAsync(TIdentity user, string recoveryCode)
  {
    if (string.IsNullOrWhiteSpace(recoveryCode)) return false;

    var hash = TokenHelper.HashToken(recoveryCode.Trim().ToUpperInvariant());
    return await _mfaStore.ConsumeRecoveryCodeHashAsync(user.IdAsString, hash);
  }
}
