namespace CWAuth.Interfaces;

public interface IUserEmailSender
{
  Task SendVerificationEmailAsync(IAccountIdentity user, string tokenUrl);
  Task SendMagicLinkAsync(IAccountIdentity user, string tokenUrl);
}
