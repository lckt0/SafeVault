using Microsoft.AspNetCore.Authorization;
using SafeVault.Models;

namespace SafeVault.Security;

public static class Policies
{
    public const string Authenticated = "Authenticated";
    public const string AdminOnly = "AdminOnly";

    public static void Configure(AuthorizationOptions options)
    {
        options.AddPolicy(Authenticated, p => p.RequireAuthenticatedUser().RequireRole(Roles.User, Roles.Admin));
        options.AddPolicy(AdminOnly, p => p.RequireAuthenticatedUser().RequireRole(Roles.Admin));
        // Any endpoint added later without an explicit policy is closed by default.
        options.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();
    }
}
