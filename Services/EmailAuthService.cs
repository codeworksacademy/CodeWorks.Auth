using CodeWorks.Auth.Extensions;
using CodeWorks.Auth.Interfaces;
using CodeWorks.Auth.Security;
using Microsoft.AspNetCore.Identity;

namespace CodeWorks.Auth.Services;

public class EmailAuthService<TAccountIdentity> where TAccountIdentity : class, IAccountIdentity
{
    private readonly IAccountIdentityStore<TAccountIdentity> _userStore;
    private readonly IUserTokenStore _tokenStore;
    private readonly IUserEmailSender _emailSender;

    public EmailAuthService(
        IAccountIdentityStore<TAccountIdentity> userStore,
        IUserTokenStore tokenStore,
        IUserEmailSender emailSender)
    {
        _userStore = userStore;
        _tokenStore = tokenStore;
        _emailSender = emailSender;
    }

    #region Email Requests

    public async Task RequestVerificationEmailAsync(string email, string callbackBaseUrl)
    {
        var user = await _userStore.FindByEmailAsync(email);
        if (user == null) return;

        var token = TokenHelper.GenerateToken();
        await _tokenStore.SaveTokenAsync(new TokenRecord
        {
            Token = token,
            UserId = user.Id,
            Purpose = EmailTokenPurpose.EmailVerification,
            ExpiresAt = DateTime.UtcNow.AddHours(48)
        });

        var url = $"{callbackBaseUrl}?token={token}";
        await _emailSender.SendVerificationEmailAsync(user, url);
    }

    public async Task RequestVerificationEmailAsync(TAccountIdentity user, string callbackBaseUrl)
    {
        var token = TokenHelper.GenerateToken();
        await _tokenStore.SaveTokenAsync(new TokenRecord
        {
            Token = token,
            UserId = user.Id,
            Purpose = EmailTokenPurpose.EmailVerification,
            ExpiresAt = DateTime.UtcNow.AddHours(48)
        });

        var url = $"{callbackBaseUrl}?token={token}";
        await _emailSender.SendVerificationEmailAsync(user, url);
    }

    public async Task RequestMagicLinkAsync(string email, string callbackBaseUrl)
    {
        var user = await _userStore.FindByEmailAsync(email);
        if (user == null) return;

        var token = TokenHelper.GenerateToken();
        await _tokenStore.SaveTokenAsync(new TokenRecord
        {
            Token = token,
            UserId = user.Id,
            Purpose = EmailTokenPurpose.MagicLinkLogin,
            ExpiresAt = DateTime.UtcNow.AddMinutes(30)
        });

        var url = $"{callbackBaseUrl}?token={token}";
        await _emailSender.SendMagicLinkAsync(user, url);
    }

    public async Task RequestPasswordResetAsync(string email, string callbackBaseUrl)
    {
        var user = await _userStore.FindByEmailAsync(email);
        if (user == null) return;

        var token = TokenHelper.GenerateToken();
        await _tokenStore.SaveTokenAsync(new TokenRecord
        {
            Token = token,
            UserId = user.Id,
            Purpose = EmailTokenPurpose.PasswordReset,
            ExpiresAt = DateTime.UtcNow.AddMinutes(30)
        });

        var url = $"{callbackBaseUrl}?token={token}";
        await _emailSender.SendPasswordResetEmailAsync(user, url);
    }

    #endregion

    #region Email Confirmations

    public async Task<bool> ConfirmEmailAsync(string token)
    {
        var record = await _tokenStore.GetValidTokenAsync(token, EmailTokenPurpose.EmailVerification);
        if (record == null || record.Used || record.ExpiresAt < DateTime.UtcNow)
            return false;

        var user = await _userStore.FindByIdAsync(record.UserId);
        if (user == null)
            return false;

        await _userStore.MarkEmailVerifiedAsync(user);
        await _tokenStore.MarkTokenUsedAsync(token);
        return true;
    }


    public async Task<TAccountIdentity?> RedeemMagicLinkAsync(string token)
    {
        var record = await _tokenStore.GetValidTokenAsync(token, EmailTokenPurpose.MagicLinkLogin);
        if (record == null || record.Used || record.ExpiresAt < DateTime.UtcNow)
            return null;

        var user = await _userStore.FindByIdAsync(record.UserId);
        if (user == null)
            return null;

        await _tokenStore.MarkTokenUsedAsync(token);
        return user;
    }

    public async Task<bool> ResetPasswordAsync(string token, string newPassword)
    {
        var record = await _tokenStore.GetValidTokenAsync(token, EmailTokenPurpose.PasswordReset);
        if (record == null || record.Used || record.ExpiresAt < DateTime.UtcNow)
            return false;

        var user = await _userStore.FindByIdAsync(record.UserId);
        if (user == null)
            return false;

        user.PasswordHash = PasswordHelper<IAccountIdentity>.HashPassword(user, newPassword);
        user.IsEmailVerified = true;
        await _userStore.SaveAsync(user);
        await _tokenStore.MarkTokenUsedAsync(token);
        return true;
    }

    #endregion
}
