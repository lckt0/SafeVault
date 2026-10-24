using System.Globalization;
using Microsoft.Data.Sqlite;
using SafeVault.Models;

namespace SafeVault.Data;

public sealed class NoteRepository(SqliteConnectionFactory db, TimeProvider clock)
{
    private const string Columns = "NoteID, OwnerID, Title, Content, CreatedUtc";

    public async Task<Note> CreateAsync(long ownerId, string title, string content, CancellationToken ct = default)
    {
        var created = clock.GetUtcNow().UtcDateTime;
        await using var connection = await db.OpenAsync(ct);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO Notes (OwnerID, Title, Content, CreatedUtc)
            VALUES ($owner, $title, $content, $created)
            RETURNING NoteID;
            """;
        command.Parameters.AddWithValue("$owner", ownerId);
        command.Parameters.AddWithValue("$title", title);
        command.Parameters.AddWithValue("$content", content);
        command.Parameters.AddWithValue("$created", created.ToString("O", CultureInfo.InvariantCulture));
        var id = (long)(await command.ExecuteScalarAsync(ct))!;
        return new Note(id, ownerId, title, content, created);
    }

    public async Task<Note?> FindAsync(long id, CancellationToken ct = default)
    {
        await using var connection = await db.OpenAsync(ct);
        await using var command = connection.CreateCommand();
        command.CommandText = $"SELECT {Columns} FROM Notes WHERE NoteID = $id;";
        command.Parameters.AddWithValue("$id", id);
        await using var reader = await command.ExecuteReaderAsync(ct);
        return await reader.ReadAsync(ct) ? Map(reader) : null;
    }

    public async Task<IReadOnlyList<Note>> ListByOwnerAsync(long ownerId, CancellationToken ct = default)
    {
        await using var connection = await db.OpenAsync(ct);
        await using var command = connection.CreateCommand();
        command.CommandText = $"SELECT {Columns} FROM Notes WHERE OwnerID = $owner ORDER BY NoteID DESC;";
        command.Parameters.AddWithValue("$owner", ownerId);
        var notes = new List<Note>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            notes.Add(Map(reader));
        return notes;
    }

    public async Task<bool> DeleteAsync(long id, CancellationToken ct = default)
    {
        await using var connection = await db.OpenAsync(ct);
        await using var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM Notes WHERE NoteID = $id;";
        command.Parameters.AddWithValue("$id", id);
        return await command.ExecuteNonQueryAsync(ct) == 1;
    }

    public async Task<long> CountAsync(CancellationToken ct = default)
    {
        await using var connection = await db.OpenAsync(ct);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM Notes;";
        return (long)(await command.ExecuteScalarAsync(ct))!;
    }

    private static Note Map(SqliteDataReader r) =>
        new(r.GetInt64(0), r.GetInt64(1), r.GetString(2), r.GetString(3),
            DateTime.Parse(r.GetString(4), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind));
}
