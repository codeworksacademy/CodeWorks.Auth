using System.Security.Cryptography;

namespace CodeWorks.Auth.Security;

public static class TokenHelper
{
    public static string GenerateToken(int size = 32)
    {
        var bytes = RandomNumberGenerator.GetBytes(size);
        return Convert.ToBase64String(bytes)
            .Replace("+", "-").Replace("/", "_").Replace("=", "");
    }
}
