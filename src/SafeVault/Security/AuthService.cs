using SafeVault.Data;
using SafeVault.Models;

namespace SafeVault.Security;

public sealed class AuthService(UserRepository users)
{
    // Verified against when the username does not exist, so a miss costs the same time as a wrong password.
    private static readonly string DummyHash = PasswordHasher.Hash(Guid.NewGuid().ToString());

    /// <summary>Self-registration always creates a plain user; roles are only granted by an admin.</summary>
    public async Task<UserRecord?> RegisterAsync(string username, string email, string password, CancellationToken ct = default) =>
        await users.CreateAsync(username, email, PasswordHasher.Hash(password), Roles.User, ct);

    public async Task<UserRecord?> AuthenticateAsync(string username, string password, CancellationToken ct = default)
    {
        var user = await users.FindByUsernameAsync(username, ct);
        if (user is null)
        {
            PasswordHasher.Verify(password, DummyHash);
            return null;
        }
        return PasswordHasher.Verify(password, user.PasswordHash) ? user : null;
    }

    /// <summary>Creates the bootstrap administrator from configuration if it does not exist yet.</summary>
    public async Task EnsureAdminAsync(string? username, string? password, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            return;
        if (InputValidator.ValidateUsername(username) is { } usernameError)
            throw new InvalidOperationException($"Seed admin username is invalid: {usernameError}");
        if (InputValidator.ValidatePassword(password) is { } passwordError)
            throw new InvalidOperationException($"Seed admin password is invalid: {passwordError}");
        if (await users.FindByUsernameAsync(username, ct) is null)
            await users.CreateAsync(username, $"{username}@safevault.local", PasswordHasher.Hash(password), Roles.Admin, ct);
    }
}
