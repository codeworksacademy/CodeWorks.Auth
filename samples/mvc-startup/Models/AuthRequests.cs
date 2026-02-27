namespace CodeWorks.Auth.MvcSample.Models;

public record RegisterRequest(string Email, string Password, string? Name);
public record LoginRequest(string Email, string Password);
public record RefreshRequest(string RefreshToken);
