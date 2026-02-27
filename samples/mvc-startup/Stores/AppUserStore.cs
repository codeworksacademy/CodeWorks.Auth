using System.Collections.Concurrent;
using CodeWorks.Auth.Interfaces;
using CodeWorks.Auth.MvcSample.Models;

namespace CodeWorks.Auth.MvcSample.Stores;

public class AppUserStore : IAccountIdentityStore<AppUser>
{
  private static readonly ConcurrentDictionary<string, AppUser> UsersById = new();

  public Task<AppUser> FindByEmailAsync(string email)
  {
    var user = UsersById.Values.FirstOrDefault(x =>
        string.Equals(x.Email, email, StringComparison.OrdinalIgnoreCase));
    return Task.FromResult(user!);
  }

  public Task<bool> EmailExistsAsync(string email)
  {
    var exists = UsersById.Values.Any(x =>
        string.Equals(x.Email, email, StringComparison.OrdinalIgnoreCase));
    return Task.FromResult(exists);
  }

  public Task<AppUser> UpdateAsync(AppUser user)
  {
    UsersById[user.Id] = user;
    return Task.FromResult(user);
  }

  public Task<AppUser> FindByIdAsync(string id)
  {
    UsersById.TryGetValue(id, out var user);
    return Task.FromResult(user!);
  }

  public Task<AppUser> FindByProviderAsync(string provider, string providerId)
  {
    var user = UsersById.Values.FirstOrDefault(x =>
        string.Equals(x.Provider, provider, StringComparison.OrdinalIgnoreCase)
        && string.Equals(x.ProviderId, providerId, StringComparison.Ordinal));
    return Task.FromResult(user!);
  }

  public Task<AppUser> CreateAsync(AppUser user)
  {
    if (string.IsNullOrWhiteSpace(user.Id))
      user.Id = Guid.NewGuid().ToString("N");

    UsersById[user.Id] = user;
    return Task.FromResult(user);
  }

  public Task DeleteAsync(string id)
  {
    UsersById.TryRemove(id, out _);
    return Task.CompletedTask;
  }
}
