namespace CodeWorks.Auth.Interfaces;

public interface IUserEmailSender
{
  Task SendVerificationEmailAsync(IAccountIdentity user, string tokenUrl);
  Task SendMagicLinkAsync(IAccountIdentity user, string tokenUrl);
  Task SendPasswordResetEmailAsync(IAccountIdentity user, string tokenUrl);
}
