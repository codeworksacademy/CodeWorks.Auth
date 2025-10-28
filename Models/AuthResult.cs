using CodeWorks.Auth.Interfaces;

namespace CodeWorks.Auth.Models;

public class AuthResult<UserT>
{
  public bool IsSuccessful { get; init; }
  public UserT? User { get; init; }
  public string? Token { get; init; }
  public string? Error { get; init; }

  public static AuthResult<UserT> Success(UserT user, string token) => new() { IsSuccessful = true, Token = token, User = user };
  public static AuthResult<UserT> Failure(string message) => new() { IsSuccessful = false, Error = message };
}
