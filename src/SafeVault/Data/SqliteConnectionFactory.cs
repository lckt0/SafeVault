using Microsoft.Data.Sqlite;

namespace SafeVault.Data;

public sealed class SqliteConnectionFactory(string connectionString)
{
    public async Task<SqliteConnection> OpenAsync(CancellationToken ct = default)
    {
        var connection = new SqliteConnection(connectionString);
        await connection.OpenAsync(ct);
        await using var pragma = connection.CreateCommand();
        pragma.CommandText = "PRAGMA foreign_keys = ON;";
        await pragma.ExecuteNonQueryAsync(ct);
        return connection;
    }

    public async Task EnsureSchemaAsync(CancellationToken ct = default)
    {
        await using var connection = await OpenAsync(ct);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS Users (
                UserID       INTEGER PRIMARY KEY AUTOINCREMENT,
                Username     TEXT NOT NULL UNIQUE COLLATE NOCASE,
                Email        TEXT NOT NULL,
                PasswordHash TEXT NOT NULL,
                Role         TEXT NOT NULL CHECK (Role IN ('user', 'admin'))
            );
            CREATE TABLE IF NOT EXISTS Notes (
                NoteID     INTEGER PRIMARY KEY AUTOINCREMENT,
                OwnerID    INTEGER NOT NULL REFERENCES Users(UserID) ON DELETE CASCADE,
                Title      TEXT NOT NULL,
                Content    TEXT NOT NULL,
                CreatedUtc TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS IX_Notes_OwnerID ON Notes(OwnerID);
            """;
        await command.ExecuteNonQueryAsync(ct);
    }
}
