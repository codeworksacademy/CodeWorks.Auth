using Microsoft.AspNetCore.Identity;

namespace CodeWorks.Auth.Extensions;

public static class PasswordHelper<TUser> where TUser : class
{
  private static readonly PasswordHasher<TUser> _hasher = new();

  public static string HashPassword(TUser user, string password)
  {
    return _hasher.HashPassword(user, password);
  }

  public static PasswordVerificationResult VerifyPassword(TUser user, string hashedPassword, string inputPassword)
  {
    var result = _hasher.VerifyHashedPassword(user, hashedPassword, inputPassword);
    return result;
  }
}