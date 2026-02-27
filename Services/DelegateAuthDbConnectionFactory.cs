using System.Data.Common;
using CodeWorks.Auth.Interfaces;

namespace CodeWorks.Auth.Services;

public class DelegateAuthDbConnectionFactory : IAuthDbConnectionFactory
{
  private readonly Func<CancellationToken, Task<DbConnection>> _openConnectionAsync;

  public DelegateAuthDbConnectionFactory(Func<CancellationToken, Task<DbConnection>> openConnectionAsync)
  {
    _openConnectionAsync = openConnectionAsync;
  }

  public Task<DbConnection> OpenConnectionAsync(CancellationToken cancellationToken = default)
  {
    return _openConnectionAsync(cancellationToken);
  }
}
