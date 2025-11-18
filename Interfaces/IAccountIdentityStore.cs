namespace CodeWorks.Auth.Interfaces;

public interface IAccountIdentityStore<TIdentity> where TIdentity : IAccountIdentity
{
  Task<TIdentity> FindByEmailAsync(string email);
  Task<bool> EmailExistsAsync(string email);
  Task<TIdentity> UpdateAsync(TIdentity user);
  Task<TIdentity> FindByIdAsync(string id);
  Task<TIdentity> FindByProviderAsync(string provider, string providerId);
  Task<TIdentity> CreateAsync(TIdentity user);
  Task DeleteAsync(string id);



  async public Task<TIdentity> MarkEmailVerifiedAsync(TIdentity user)
  {
    if (user == null) throw new ArgumentNullException(nameof(user));
    user.IsEmailVerified = true;
    await UpdateAsync(user);
    return user;
  }

  async public Task<bool> IsEmailVerifiedAsync(string email)
  {
    var user = await FindByEmailAsync(email);
    return user != null && user.IsEmailVerified;
  }

}