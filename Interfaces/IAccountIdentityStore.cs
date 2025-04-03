namespace CWAuth.Interfaces;

public interface IAccountIdentityStore<TIdentity> where TIdentity : IAccountIdentity
{
  Task<TIdentity?> FindByEmailAsync(string email);
  Task<bool> EmailExistsAsync(string email);
  Task SaveAsync(TIdentity user);
  Task<TIdentity?> FindByIdAsync(string id);

  async public Task<TIdentity> MarkEmailVerifiedAsync(TIdentity user)
  {
    if (user == null) throw new ArgumentNullException(nameof(user));
    user.IsEmailVerified = true;
    await SaveAsync(user);
    return user;
  }


}
