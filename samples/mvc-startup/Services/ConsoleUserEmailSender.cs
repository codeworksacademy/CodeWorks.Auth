using CodeWorks.Auth.Interfaces;
using Microsoft.Extensions.Logging;

namespace CodeWorks.Auth.MvcSample.Services;

public class ConsoleUserEmailSender : IUserEmailSender
{
  private readonly ILogger<ConsoleUserEmailSender> _logger;

  public ConsoleUserEmailSender(ILogger<ConsoleUserEmailSender> logger)
  {
    _logger = logger;
  }

  public Task SendVerificationEmailAsync(IAccountIdentityBase user, string tokenUrl)
  {
    _logger.LogInformation("Verification email for {Email}: {Url}", user.Email, tokenUrl);
    return Task.CompletedTask;
  }

  public Task SendMagicLinkAsync(IAccountIdentityBase user, string tokenUrl)
  {
    _logger.LogInformation("Magic link email for {Email}: {Url}", user.Email, tokenUrl);
    return Task.CompletedTask;
  }

  public Task SendPasswordResetEmailAsync(IAccountIdentityBase user, string tokenUrl)
  {
    _logger.LogInformation("Password reset email for {Email}: {Url}", user.Email, tokenUrl);
    return Task.CompletedTask;
  }
}
