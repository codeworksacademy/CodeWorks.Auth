using System.Data;
using System.Data.Common;
using CodeWorks.Auth.Interfaces;
using CodeWorks.Auth.Models;

namespace CodeWorks.Auth.Services;

public class DbPasskeyCredentialStore : IPasskeyCredentialStore
{
  private readonly IAuthDbConnectionFactory _connectionFactory;

  public DbPasskeyCredentialStore(IAuthDbConnectionFactory connectionFactory)
  {
    _connectionFactory = connectionFactory;
  }

  public async Task SaveAsync(PasskeyCredentialRecord credential)
  {
    await using var connection = await _connectionFactory.OpenConnectionAsync();
    await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted);

    var existing = await GetInternalAsync(connection, transaction, credential.CredentialId);
    if (existing == null)
    {
      const string insertSql = """
          INSERT INTO auth_passkey_credentials
          (credential_id, user_id, public_key, sign_count, created_at, last_used_at)
          VALUES
          (@credential_id, @user_id, @public_key, @sign_count, @created_at, @last_used_at)
          """;

      await ExecuteNonQueryAsync(connection, transaction, insertSql, command =>
      {
        AddParameter(command, "credential_id", credential.CredentialId);
        AddParameter(command, "user_id", credential.UserId);
        AddParameter(command, "public_key", credential.PublicKey);
        AddParameter(command, "sign_count", (long)credential.SignCount);
        AddParameter(command, "created_at", credential.CreatedAt);
        AddParameter(command, "last_used_at", credential.LastUsedAt);
      });
    }
    else
    {
      const string updateSql = """
          UPDATE auth_passkey_credentials
          SET user_id = @user_id,
              public_key = @public_key,
              sign_count = @sign_count,
              created_at = @created_at,
              last_used_at = @last_used_at
          WHERE credential_id = @credential_id
          """;

      await ExecuteNonQueryAsync(connection, transaction, updateSql, command =>
      {
        AddParameter(command, "credential_id", credential.CredentialId);
        AddParameter(command, "user_id", credential.UserId);
        AddParameter(command, "public_key", credential.PublicKey);
        AddParameter(command, "sign_count", (long)credential.SignCount);
        AddParameter(command, "created_at", credential.CreatedAt);
        AddParameter(command, "last_used_at", credential.LastUsedAt);
      });
    }

    await transaction.CommitAsync();
  }

  public async Task<PasskeyCredentialRecord?> GetAsync(string credentialId)
  {
    await using var connection = await _connectionFactory.OpenConnectionAsync();
    return await GetInternalAsync(connection, null, credentialId);
  }

  public async Task<IReadOnlyList<PasskeyCredentialRecord>> GetByUserIdAsync(string userId)
  {
    await using var connection = await _connectionFactory.OpenConnectionAsync();

    const string sql = """
        SELECT credential_id, user_id, public_key, sign_count, created_at, last_used_at
        FROM auth_passkey_credentials
        WHERE user_id = @user_id
        """;

    await using var command = connection.CreateCommand();
    command.CommandText = sql;
    AddParameter(command, "user_id", userId);

    var results = new List<PasskeyCredentialRecord>();
    await using var reader = await command.ExecuteReaderAsync();
    while (await reader.ReadAsync())
    {
      results.Add(new PasskeyCredentialRecord
      {
        CredentialId = reader.GetString(0),
        UserId = reader.GetString(1),
        PublicKey = reader.GetString(2),
        SignCount = Convert.ToUInt32(reader.GetInt64(3)),
        CreatedAt = reader.GetDateTime(4),
        LastUsedAt = reader.IsDBNull(5) ? null : reader.GetDateTime(5)
      });
    }

    return results;
  }

  public async Task UpdateUsageAsync(string credentialId, uint newSignCount, DateTime usedAtUtc)
  {
    await using var connection = await _connectionFactory.OpenConnectionAsync();

    const string sql = """
        UPDATE auth_passkey_credentials
        SET sign_count = @sign_count,
            last_used_at = @last_used_at
        WHERE credential_id = @credential_id
        """;

    await ExecuteNonQueryAsync(connection, null, sql, command =>
    {
      AddParameter(command, "credential_id", credentialId);
      AddParameter(command, "sign_count", (long)newSignCount);
      AddParameter(command, "last_used_at", usedAtUtc);
    });
  }

  private static async Task<PasskeyCredentialRecord?> GetInternalAsync(
      DbConnection connection,
      DbTransaction? transaction,
      string credentialId)
  {
    const string sql = """
        SELECT credential_id, user_id, public_key, sign_count, created_at, last_used_at
        FROM auth_passkey_credentials
        WHERE credential_id = @credential_id
        """;

    await using var command = connection.CreateCommand();
    command.Transaction = transaction;
    command.CommandText = sql;
    AddParameter(command, "credential_id", credentialId);

    await using var reader = await command.ExecuteReaderAsync();
    if (!await reader.ReadAsync())
      return null;

    return new PasskeyCredentialRecord
    {
      CredentialId = reader.GetString(0),
      UserId = reader.GetString(1),
      PublicKey = reader.GetString(2),
      SignCount = Convert.ToUInt32(reader.GetInt64(3)),
      CreatedAt = reader.GetDateTime(4),
      LastUsedAt = reader.IsDBNull(5) ? null : reader.GetDateTime(5)
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
