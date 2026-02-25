using System.Data;
using System.Data.Common;
using CodeWorks.Auth.Interfaces;
using CodeWorks.Auth.Models;

namespace CodeWorks.Auth.Services;

public class DbPasskeyChallengeStore : IPasskeyChallengeStore
{
  private readonly IAuthDbConnectionFactory _connectionFactory;

  public DbPasskeyChallengeStore(IAuthDbConnectionFactory connectionFactory)
  {
    _connectionFactory = connectionFactory;
  }

  public async Task SaveAsync(PasskeyChallengeRecord challenge)
  {
    await using var connection = await _connectionFactory.OpenConnectionAsync();
    await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted);

    await ExecuteNonQueryAsync(connection, transaction,
      "DELETE FROM auth_passkey_challenges WHERE challenge = @challenge",
      command => AddParameter(command, "challenge", challenge.Challenge));

    const string insertSql = """
        INSERT INTO auth_passkey_challenges
        (challenge, user_id, purpose, created_at, expires_at)
        VALUES
        (@challenge, @user_id, @purpose, @created_at, @expires_at)
        """;

    await ExecuteNonQueryAsync(connection, transaction, insertSql, command =>
    {
      AddParameter(command, "challenge", challenge.Challenge);
      AddParameter(command, "user_id", challenge.UserId);
      AddParameter(command, "purpose", (int)challenge.Purpose);
      AddParameter(command, "created_at", challenge.CreatedAt);
      AddParameter(command, "expires_at", challenge.ExpiresAt);
    });

    await transaction.CommitAsync();
  }

  public async Task<PasskeyChallengeRecord?> ConsumeAsync(
      string challenge,
      PasskeyChallengePurpose expectedPurpose,
      string? expectedUserId = null)
  {
    await using var connection = await _connectionFactory.OpenConnectionAsync();
    await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable);

    const string selectSql = """
        SELECT challenge, user_id, purpose, created_at, expires_at
        FROM auth_passkey_challenges
        WHERE challenge = @challenge
        """;

    await using var selectCommand = connection.CreateCommand();
    selectCommand.Transaction = transaction;
    selectCommand.CommandText = selectSql;
    AddParameter(selectCommand, "challenge", challenge);

    PasskeyChallengeRecord? record = null;
    await using (var reader = await selectCommand.ExecuteReaderAsync())
    {
      if (await reader.ReadAsync())
      {
        record = new PasskeyChallengeRecord
        {
          Challenge = reader.GetString(0),
          UserId = reader.IsDBNull(1) ? null : reader.GetString(1),
          Purpose = (PasskeyChallengePurpose)reader.GetInt32(2),
          CreatedAt = reader.GetDateTime(3),
          ExpiresAt = reader.GetDateTime(4)
        };
      }
    }

    if (record == null)
    {
      await transaction.CommitAsync();
      return null;
    }

    if (record.Purpose != expectedPurpose || record.ExpiresAt <= DateTime.UtcNow)
    {
      await ExecuteNonQueryAsync(connection, transaction,
          "DELETE FROM auth_passkey_challenges WHERE challenge = @challenge",
          command => AddParameter(command, "challenge", challenge));
      await transaction.CommitAsync();
      return null;
    }

    if (!string.IsNullOrWhiteSpace(expectedUserId) &&
        !string.Equals(record.UserId, expectedUserId, StringComparison.Ordinal))
    {
      await ExecuteNonQueryAsync(connection, transaction,
          "DELETE FROM auth_passkey_challenges WHERE challenge = @challenge",
          command => AddParameter(command, "challenge", challenge));
      await transaction.CommitAsync();
      return null;
    }

    var deleted = await ExecuteNonQueryAsync(connection, transaction,
        "DELETE FROM auth_passkey_challenges WHERE challenge = @challenge",
        command => AddParameter(command, "challenge", challenge));

    await transaction.CommitAsync();
    return deleted == 1 ? record : null;
  }

  public async Task CleanupExpiredAsync()
  {
    await using var connection = await _connectionFactory.OpenConnectionAsync();
    await ExecuteNonQueryAsync(connection, transaction: null,
      "DELETE FROM auth_passkey_challenges WHERE expires_at <= @now",
      command => AddParameter(command, "now", DateTime.UtcNow));
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
