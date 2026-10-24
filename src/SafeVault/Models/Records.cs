namespace SafeVault.Models;

public sealed record UserRecord(long Id, string Username, string Email, string PasswordHash, string Role);

public sealed record Note(long Id, long OwnerId, string Title, string Content, DateTime CreatedUtc);
