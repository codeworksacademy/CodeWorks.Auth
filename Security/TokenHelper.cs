using System.Security.Cryptography;
using System.Text;

namespace CodeWorks.Auth.Security;

public static class TokenHelper
{
    public static string GenerateToken(int size = 32)
    {
        var bytes = RandomNumberGenerator.GetBytes(size);
        return Convert.ToBase64String(bytes)
            .Replace("+", "-").Replace("/", "_").Replace("=", "");
    }

    public static string HashToken(string token)
    {
        if (string.IsNullOrWhiteSpace(token))
            return string.Empty;

        var bytes = Encoding.UTF8.GetBytes(token.Trim());
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash);
    }
}
