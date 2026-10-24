using SafeVault.Models;
using SafeVault.Security;

namespace SafeVault.Endpoints;

public static class AuthEndpoints
{
    public const string RateLimitPolicy = "auth";

    public static void MapAuthEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/auth").AllowAnonymous().RequireRateLimiting(RateLimitPolicy);

        group.MapPost("/register", async (RegisterRequest request, AuthService auth, CancellationToken ct) =>
        {
            var validation = new Validation()
                .Check("username", InputValidator.ValidateUsername(request.Username))
                .Check("email", InputValidator.ValidateEmail(request.Email))
                .Check("password", InputValidator.ValidatePassword(request.Password));
            if (!validation.IsValid)
                return validation.Problem();

            var user = await auth.RegisterAsync(request.Username!, request.Email!, request.Password!, ct);
            return user is null
                ? Results.Problem("Username is already taken.", statusCode: StatusCodes.Status409Conflict)
                : Results.Created("/api/users/me", new UserResponse(user.Id, user.Username, user.Email, user.Role));
        });

        group.MapPost("/login", async (LoginRequest request, AuthService auth, TokenService tokens, CancellationToken ct) =>
        {
            // Malformed credentials get the same generic 401 as wrong ones: no hint about which part failed.
            if (InputValidator.ValidateUsername(request.Username) is not null || string.IsNullOrEmpty(request.Password)
                || request.Password.Length > InputValidator.PasswordMax)
                return InvalidCredentials();

            var user = await auth.AuthenticateAsync(request.Username!, request.Password, ct);
            return user is null ? InvalidCredentials() : Results.Ok(tokens.Issue(user));
        });
    }

    private static IResult InvalidCredentials() =>
        Results.Problem("Invalid username or password.", statusCode: StatusCodes.Status401Unauthorized);
}
