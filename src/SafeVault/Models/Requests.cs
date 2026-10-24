namespace SafeVault.Models;

public sealed record RegisterRequest(string? Username, string? Email, string? Password);

public sealed record LoginRequest(string? Username, string? Password);

public sealed record CreateNoteRequest(string? Title, string? Content);

public sealed record ChangeRoleRequest(string? Role);

public sealed record UserResponse(long Id, string Username, string Email, string Role);

public sealed record NoteResponse(long Id, string Title, string Content, DateTime CreatedUtc)
{
    public static NoteResponse From(Note note) => new(note.Id, note.Title, note.Content, note.CreatedUtc);
}

public sealed record TokenResponse(string AccessToken, DateTime ExpiresUtc, string Role);
