using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Security;

namespace SafeVault.Endpoints;

public static class AdminEndpoints
{
    public static void MapAdminEndpoints(this IEndpointRouteBuilder app)
    {
        var admin = app.MapGroup("/api/admin").RequireAuthorization(Policies.AdminOnly);

        admin.MapGet("/dashboard", async (UserRepository users, NoteRepository notes, CancellationToken ct) =>
            Results.Ok(new { users = await users.CountAsync(ct), notes = await notes.CountAsync(ct) }));

        admin.MapGet("/users", async (string? search, UserRepository users, CancellationToken ct) =>
        {
            var term = search ?? "";
            if (term.Length > InputValidator.UsernameMax)
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["search"] = [$"Search term must be at most {InputValidator.UsernameMax} characters."],
                });

            var found = await users.SearchAsync(term, ct);
            return Results.Ok(found.Select(u => new UserResponse(u.Id, u.Username, u.Email, u.Role)));
        });

        admin.MapPut("/users/{username}/role", async (string username, ChangeRoleRequest request, UserRepository users, CancellationToken ct) =>
        {
            var validation = new Validation()
                .Check("username", InputValidator.ValidateUsername(username))
                .Check("role", InputValidator.ValidateRole(request.Role));
            if (!validation.IsValid)
                return validation.Problem();

            return await users.UpdateRoleAsync(username, request.Role!, ct) ? Results.NoContent() : Results.NotFound();
        });
    }
}
