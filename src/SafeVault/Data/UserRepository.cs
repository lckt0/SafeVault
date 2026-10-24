using Microsoft.Data.Sqlite;
using SafeVault.Models;

namespace SafeVault.Data;

/// <summary>
/// All SQL in this class is static text; user input is only ever bound through SqliteParameter,
/// so it is treated as data and can never change the shape of a query.
/// </summary>
public sealed class UserRepository(SqliteConnectionFactory db)
{
    private const int SqliteConstraint = 19;
    private const string Columns = "UserID, Username, Email, PasswordHash, Role";

    public async Task<UserRecord?> FindByUsernameAsync(string username, CancellationToken ct = default)
    {
        await using var connection = await db.OpenAsync(ct);
        await using var command = connection.CreateCommand();
        command.CommandText = $"SELECT {Columns} FROM Users WHERE Username = $username;";
        command.Parameters.AddWithValue("$username", username);
        await using var reader = await command.ExecuteReaderAsync(ct);
        return await reader.ReadAsync(ct) ? Map(reader) : null;
    }

    public async Task<UserRecord?> FindByIdAsync(long id, CancellationToken ct = default)
    {
        await using var connection = await db.OpenAsync(ct);
        await using var command = connection.CreateCommand();
        command.CommandText = $"SELECT {Columns} FROM Users WHERE UserID = $id;";
        command.Parameters.AddWithValue("$id", id);
        await using var reader = await command.ExecuteReaderAsync(ct);
        return await reader.ReadAsync(ct) ? Map(reader) : null;
    }

    /// <summary>Inserts a user and returns it, or null when the username is already taken.</summary>
    public async Task<UserRecord?> CreateAsync(string username, string email, string passwordHash, string role, CancellationToken ct = default)
    {
        await using var connection = await db.OpenAsync(ct);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO Users (Username, Email, PasswordHash, Role)
            VALUES ($username, $email, $hash, $role)
            RETURNING UserID;
            """;
        command.Parameters.AddWithValue("$username", username);
        command.Parameters.AddWithValue("$email", email);
        command.Parameters.AddWithValue("$hash", passwordHash);
        command.Parameters.AddWithValue("$role", role);
        try
        {
            var id = (long)(await command.ExecuteScalarAsync(ct))!;
            return new UserRecord(id, username, email, passwordHash, role);
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == SqliteConstraint)
        {
            return null;
        }
    }

    /// <summary>Case-insensitive "contains" search. LIKE wildcards in the term are escaped so they match literally.</summary>
    public async Task<IReadOnlyList<UserRecord>> SearchAsync(string term, CancellationToken ct = default)
    {
        var escaped = term.Replace(@"\", @"\\").Replace("%", @"\%").Replace("_", @"\_");
        await using var connection = await db.OpenAsync(ct);
        await using var command = connection.CreateCommand();
        command.CommandText = $"""
            SELECT {Columns} FROM Users
            WHERE Username LIKE $pattern ESCAPE '\'
            ORDER BY Username LIMIT 50;
            """;
        command.Parameters.AddWithValue("$pattern", $"%{escaped}%");
        var users = new List<UserRecord>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            users.Add(Map(reader));
        return users;
    }

    public async Task<bool> UpdateRoleAsync(string username, string role, CancellationToken ct = default)
    {
        await using var connection = await db.OpenAsync(ct);
        await using var command = connection.CreateCommand();
        command.CommandText = "UPDATE Users SET Role = $role WHERE Username = $username;";
        command.Parameters.AddWithValue("$role", role);
        command.Parameters.AddWithValue("$username", username);
        return await command.ExecuteNonQueryAsync(ct) == 1;
    }

    public async Task<long> CountAsync(CancellationToken ct = default)
    {
        await using var connection = await db.OpenAsync(ct);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM Users;";
        return (long)(await command.ExecuteScalarAsync(ct))!;
    }

    private static UserRecord Map(SqliteDataReader r) =>
        new(r.GetInt64(0), r.GetString(1), r.GetString(2), r.GetString(3), r.GetString(4));
}
