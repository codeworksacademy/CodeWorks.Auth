using CWAuth.Interfaces;

public class AuthResult
{
  public bool IsSuccessful { get; init; }
  public string? Token { get; init; }
  public string? Error { get; init; }

  public static AuthResult Success(IAccountIdentity user, string token) => new() { IsSuccessful = true, Token = token };
  public static AuthResult Failure(string message) => new() { IsSuccessful = false, Error = message };
}
