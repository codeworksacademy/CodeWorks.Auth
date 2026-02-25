namespace CodeWorks.Auth.Models;

public class PasskeyOperationResult
{
  public bool IsSuccessful { get; init; }
  public string? OptionsJson { get; init; }
  public string? Error { get; init; }

  public static PasskeyOperationResult Success(string optionsJson = "{}") =>
      new() { IsSuccessful = true, OptionsJson = optionsJson };

  public static PasskeyOperationResult Failure(string error) =>
      new() { IsSuccessful = false, Error = error };
}
