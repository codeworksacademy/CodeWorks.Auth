using System.Collections.Concurrent;
using CodeWorks.Auth.Interfaces;
using CodeWorks.Auth.Models;

namespace CodeWorks.Auth.MvcSample.Stores;

public class InMemoryUserTokenStore : IUserTokenStore
{
  private static readonly ConcurrentDictionary<string, TokenRecord> Tokens = new();

  public Task SaveTokenAsync(TokenRecord token)
  {
    Tokens[token.Token] = token;
    return Task.CompletedTask;
  }

  public Task<TokenRecord> GetValidTokenAsync(string token, EmailTokenPurpose purpose)
  {
    Tokens.TryGetValue(token, out var record);
    if (record == null || record.Purpose != purpose)
      return Task.FromResult<TokenRecord>(null!);

    return Task.FromResult(record);
  }

  public Task MarkTokenUsedAsync(string token)
  {
    if (Tokens.TryGetValue(token, out var record))
    {
      record.Used = true;
      Tokens[token] = record;
    }

    return Task.CompletedTask;
  }
}
