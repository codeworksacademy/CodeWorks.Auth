namespace CodeWorks.Auth.Interfaces;

public interface IUserEmailSender
{
  Task SendVerificationEmailAsync(IAccountIdentityBase user, string tokenUrl);
  Task SendMagicLinkAsync(IAccountIdentityBase user, string tokenUrl);
  Task SendPasswordResetEmailAsync(IAccountIdentityBase user, string tokenUrl);
}
