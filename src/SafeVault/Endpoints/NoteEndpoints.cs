using System.Security.Claims;
using System.Text.Encodings.Web;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Security;

namespace SafeVault.Endpoints;

public static class NoteEndpoints
{
    public static void MapNoteEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/api/users/me", async (ClaimsPrincipal principal, UserRepository users, CancellationToken ct) =>
            await users.FindByIdAsync(principal.GetUserId(), ct) is { } user
                ? Results.Ok(new UserResponse(user.Id, user.Username, user.Email, user.Role))
                : Results.NotFound())
            .RequireAuthorization(Policies.Authenticated);

        var notes = app.MapGroup("/api/notes").RequireAuthorization(Policies.Authenticated);

        notes.MapGet("/", async (ClaimsPrincipal principal, NoteRepository repo, CancellationToken ct) =>
            Results.Ok((await repo.ListByOwnerAsync(principal.GetUserId(), ct)).Select(NoteResponse.From)));

        notes.MapPost("/", async (CreateNoteRequest request, ClaimsPrincipal principal, NoteRepository repo, CancellationToken ct) =>
        {
            var validation = new Validation()
                .Check("title", InputValidator.ValidateNoteTitle(request.Title))
                .Check("content", InputValidator.ValidateNoteContent(request.Content));
            if (!validation.IsValid)
                return validation.Problem();

            var note = await repo.CreateAsync(principal.GetUserId(), request.Title!, request.Content!, ct);
            return Results.Created($"/api/notes/{note.Id}", NoteResponse.From(note));
        });

        notes.MapGet("/{id:long}", async (long id, ClaimsPrincipal principal, NoteRepository repo, CancellationToken ct) =>
            await FindAccessibleAsync(id, principal, repo, ct) is { } note
                ? Results.Ok(NoteResponse.From(note))
                : Results.NotFound());

        // Server-rendered HTML view: every user-supplied value is HTML-encoded before it reaches the markup.
        notes.MapGet("/{id:long}/preview", async (long id, ClaimsPrincipal principal, NoteRepository repo, CancellationToken ct) =>
        {
            if (await FindAccessibleAsync(id, principal, repo, ct) is not { } note)
                return Results.NotFound();

            var encoder = HtmlEncoder.Default;
            var html = $"""
                <!doctype html>
                <html lang="en">
                <head><meta charset="utf-8"><title>{encoder.Encode(note.Title)}</title></head>
                <body>
                <h1>{encoder.Encode(note.Title)}</h1>
                <pre>{encoder.Encode(note.Content)}</pre>
                </body>
                </html>
                """;
            return Results.Content(html, "text/html; charset=utf-8");
        });

        notes.MapDelete("/{id:long}", async (long id, ClaimsPrincipal principal, NoteRepository repo, CancellationToken ct) =>
            await FindAccessibleAsync(id, principal, repo, ct) is { } note && await repo.DeleteAsync(note.Id, ct)
                ? Results.NoContent()
                : Results.NotFound());
    }

    /// <summary>
    /// Object-level authorization: a note is visible to its owner and to admins only.
    /// Other users get 404 so they cannot even learn that the id exists.
    /// </summary>
    private static async Task<Note?> FindAccessibleAsync(long id, ClaimsPrincipal principal, NoteRepository repo, CancellationToken ct)
    {
        var note = await repo.FindAsync(id, ct);
        return note is not null && (note.OwnerId == principal.GetUserId() || principal.IsInRole(Roles.Admin)) ? note : null;
    }
}
