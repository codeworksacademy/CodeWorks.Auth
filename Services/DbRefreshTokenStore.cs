using System.Data;
using System.Data.Common;
using CodeWorks.Auth.Interfaces;
using CodeWorks.Auth.Models;

namespace CodeWorks.Auth.Services;

public class DbRefreshTokenStore : IRefreshTokenStore
{
  private readonly IAuthDbConnectionFactory _connectionFactory;
  private readonly AuthStoreOptions _options;

  public DbRefreshTokenStore(IAuthDbConnectionFactory connectionFactory, AuthStoreOptions options)
  {
    _connectionFactory = connectionFactory;
    _options = options;
  }

  public async Task SaveTokenAsync(RefreshTokenRecord token)
  {
    await using var connection = await _connectionFactory.OpenConnectionAsync();
    await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted);

    var existing = await GetTokenInternalAsync(connection, transaction, token.TokenHash);
    if (existing == null)
    {
      const string insertSql = """
          INSERT INTO auth_refresh_tokens
          (token_hash, user_id, created_at, expires_at, revoked_at, replaced_by_token_hash)
          VALUES
          (@token_hash, @user_id, @created_at, @expires_at, @revoked_at, @replaced_by_token_hash)
          """;

      await ExecuteNonQueryAsync(connection, transaction, insertSql, parameters =>
      {
        AddParameter(parameters, "token_hash", token.TokenHash);
        AddParameter(parameters, "user_id", token.UserId);
        AddParameter(parameters, "created_at", token.CreatedAt);
        AddParameter(parameters, "expires_at", token.ExpiresAt);
        AddParameter(parameters, "revoked_at", token.RevokedAt);
        AddParameter(parameters, "replaced_by_token_hash", token.ReplacedByTokenHash);
      });
    }
    else
    {
      const string updateSql = """
          UPDATE auth_refresh_tokens
          SET user_id = @user_id,
              created_at = @created_at,
              expires_at = @expires_at,
              revoked_at = @revoked_at,
              replaced_by_token_hash = @replaced_by_token_hash
          WHERE token_hash = @token_hash
          """;

      await ExecuteNonQueryAsync(connection, transaction, updateSql, parameters =>
      {
        AddParameter(parameters, "token_hash", token.TokenHash);
        AddParameter(parameters, "user_id", token.UserId);
        AddParameter(parameters, "created_at", token.CreatedAt);
        AddParameter(parameters, "expires_at", token.ExpiresAt);
        AddParameter(parameters, "revoked_at", token.RevokedAt);
        AddParameter(parameters, "replaced_by_token_hash", token.ReplacedByTokenHash);
      });
    }

    await transaction.CommitAsync();
  }

  public async Task<RefreshTokenRecord?> GetTokenAsync(string tokenHash)
  {
    await using var connection = await _connectionFactory.OpenConnectionAsync();
    return await GetTokenInternalAsync(connection, transaction: null, tokenHash);
  }

  public async Task<RefreshTokenRecord?> TryConsumeActiveTokenAsync(string tokenHash)
  {
    await using var connection = await _connectionFactory.OpenConnectionAsync();
    await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable);

    var token = await GetTokenInternalAsync(connection, transaction, tokenHash);
    if (token == null)
    {
      await transaction.CommitAsync();
      return null;
    }

    var now = DateTime.UtcNow;
    if (!token.IsActive)
    {
      if (token.ExpiresAt <= now)
      {
        await ExecuteNonQueryAsync(connection, transaction,
          "DELETE FROM auth_refresh_tokens WHERE token_hash = @token_hash",
          parameters => AddParameter(parameters, "token_hash", tokenHash));
      }

      await transaction.CommitAsync();
      return null;
    }

    const string consumeSql = """
        UPDATE auth_refresh_tokens
        SET revoked_at = @revoked_at
        WHERE token_hash = @token_hash
          AND revoked_at IS NULL
          AND expires_at > @now
        """;

    var rows = await ExecuteNonQueryAsync(connection, transaction, consumeSql, parameters =>
    {
      AddParameter(parameters, "revoked_at", now);
      AddParameter(parameters, "token_hash", tokenHash);
      AddParameter(parameters, "now", now);
    });

    if (rows != 1)
    {
      await transaction.CommitAsync();
      return null;
    }

    token.RevokedAt = now;
    await transaction.CommitAsync();
    return token;
  }

  public async Task RevokeTokenAsync(string tokenHash, string? replacedByTokenHash = null)
  {
    await using var connection = await _connectionFactory.OpenConnectionAsync();

    const string sql = """
        UPDATE auth_refresh_tokens
        SET revoked_at = COALESCE(revoked_at, @revoked_at),
            replaced_by_token_hash = COALESCE(@replaced_by_token_hash, replaced_by_token_hash)
        WHERE token_hash = @token_hash
        """;

    await ExecuteNonQueryAsync(connection, transaction: null, sql, parameters =>
    {
      AddParameter(parameters, "revoked_at", DateTime.UtcNow);
      AddParameter(parameters, "replaced_by_token_hash", replacedByTokenHash);
      AddParameter(parameters, "token_hash", tokenHash);
    });
  }

  public async Task CleanupExpiredAsync()
  {
    await using var connection = await _connectionFactory.OpenConnectionAsync();

    var now = DateTime.UtcNow;
    var revokedBefore = now.Subtract(_options.RevokedTokenRetention);

    const string sql = """
        DELETE FROM auth_refresh_tokens
        WHERE expires_at <= @now
           OR (revoked_at IS NOT NULL AND revoked_at <= @revoked_before)
        """;

    await ExecuteNonQueryAsync(connection, transaction: null, sql, parameters =>
    {
      AddParameter(parameters, "now", now);
      AddParameter(parameters, "revoked_before", revokedBefore);
    });
  }

  private static async Task<RefreshTokenRecord?> GetTokenInternalAsync(
      DbConnection connection,
      DbTransaction? transaction,
      string tokenHash)
  {
    const string sql = """
        SELECT token_hash, user_id, created_at, expires_at, revoked_at, replaced_by_token_hash
        FROM auth_refresh_tokens
        WHERE token_hash = @token_hash
        """;

    await using var command = connection.CreateCommand();
    command.Transaction = transaction;
    command.CommandText = sql;
    AddParameter(command, "token_hash", tokenHash);

    await using var reader = await command.ExecuteReaderAsync();
    if (!await reader.ReadAsync())
      return null;

    return new RefreshTokenRecord
    {
      TokenHash = reader.GetString(0),
      UserId = reader.GetString(1),
      CreatedAt = reader.GetDateTime(2),
      ExpiresAt = reader.GetDateTime(3),
      RevokedAt = reader.IsDBNull(4) ? null : reader.GetDateTime(4),
      ReplacedByTokenHash = reader.IsDBNull(5) ? null : reader.GetString(5)
    };
  }

  private static async Task<int> ExecuteNonQueryAsync(
      DbConnection connection,
      DbTransaction? transaction,
      string sql,
      Action<DbCommand> bind)
  {
    await using var command = connection.CreateCommand();
    command.Transaction = transaction;
    command.CommandText = sql;
    bind(command);
    return await command.ExecuteNonQueryAsync();
  }

  private static void AddParameter(DbCommand command, string name, object? value)
  {
    var parameter = command.CreateParameter();
    parameter.ParameterName = $"@{name}";
    parameter.Value = value ?? DBNull.Value;
    command.Parameters.Add(parameter);
  }
}
