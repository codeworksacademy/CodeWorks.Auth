using System.Security.Cryptography;
using System.Text;

namespace CodeWorks.Auth.Security;

public static class TotpHelper
{
  private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

  public static string GenerateSecret(int size = 20)
  {
    var bytes = RandomNumberGenerator.GetBytes(size);
    return ToBase32(bytes);
  }

  public static bool VerifyCode(string base32Secret, string code, int stepSeconds = 30, int digits = 6, int allowedTimeSteps = 1)
  {
    if (string.IsNullOrWhiteSpace(base32Secret) || string.IsNullOrWhiteSpace(code))
      return false;

    if (!int.TryParse(code, out _))
      return false;

    var now = DateTimeOffset.UtcNow;
    for (var i = -allowedTimeSteps; i <= allowedTimeSteps; i++)
    {
      var candidate = ComputeCode(base32Secret, now.AddSeconds(i * stepSeconds), stepSeconds, digits);
      if (FixedTimeEquals(candidate, code))
        return true;
    }

    return false;
  }

  public static string BuildAuthenticatorUri(string issuer, string accountName, string secret)
  {
    var encodedIssuer = Uri.EscapeDataString(issuer);
    var encodedAccount = Uri.EscapeDataString(accountName);
    return $"otpauth://totp/{encodedIssuer}:{encodedAccount}?secret={secret}&issuer={encodedIssuer}&algorithm=SHA1&digits=6&period=30";
  }

  private static string ComputeCode(string base32Secret, DateTimeOffset timestamp, int stepSeconds, int digits)
  {
    var secretBytes = FromBase32(base32Secret);
    var counter = BitConverter.GetBytes(timestamp.ToUnixTimeSeconds() / stepSeconds);
    if (BitConverter.IsLittleEndian)
      Array.Reverse(counter);

    using var hmac = new HMACSHA1(secretBytes);
    var hash = hmac.ComputeHash(counter);
    var offset = hash[^1] & 0x0F;
    var binary = ((hash[offset] & 0x7F) << 24)
               | (hash[offset + 1] << 16)
               | (hash[offset + 2] << 8)
               | hash[offset + 3];

    var otp = binary % (int)Math.Pow(10, digits);
    return otp.ToString(new string('0', digits));
  }

  private static bool FixedTimeEquals(string left, string right)
  {
    var leftBytes = Encoding.UTF8.GetBytes(left);
    var rightBytes = Encoding.UTF8.GetBytes(right);
    return CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
  }

  private static string ToBase32(byte[] data)
  {
    if (data.Length == 0) return string.Empty;

    var output = new StringBuilder((data.Length + 4) / 5 * 8);
    var bitBuffer = 0;
    var bitsInBuffer = 0;

    foreach (var b in data)
    {
      bitBuffer = (bitBuffer << 8) | b;
      bitsInBuffer += 8;

      while (bitsInBuffer >= 5)
      {
        var index = (bitBuffer >> (bitsInBuffer - 5)) & 31;
        output.Append(Alphabet[index]);
        bitsInBuffer -= 5;
      }
    }

    if (bitsInBuffer > 0)
    {
      var index = (bitBuffer << (5 - bitsInBuffer)) & 31;
      output.Append(Alphabet[index]);
    }

    return output.ToString();
  }

  private static byte[] FromBase32(string input)
  {
    input = input.Trim().TrimEnd('=').ToUpperInvariant();
    if (input.Length == 0) return [];

    var output = new List<byte>(input.Length * 5 / 8);
    var bitBuffer = 0;
    var bitsInBuffer = 0;

    foreach (var c in input)
    {
      var index = Alphabet.IndexOf(c);
      if (index < 0)
        continue;

      bitBuffer = (bitBuffer << 5) | index;
      bitsInBuffer += 5;

      if (bitsInBuffer >= 8)
      {
        output.Add((byte)((bitBuffer >> (bitsInBuffer - 8)) & 0xFF));
        bitsInBuffer -= 8;
      }
    }

    return output.ToArray();
  }
}
