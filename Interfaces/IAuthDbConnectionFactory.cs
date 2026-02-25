using System.Data.Common;

namespace CodeWorks.Auth.Interfaces;

public interface IAuthDbConnectionFactory
{
  Task<DbConnection> OpenConnectionAsync(CancellationToken cancellationToken = default);
}
