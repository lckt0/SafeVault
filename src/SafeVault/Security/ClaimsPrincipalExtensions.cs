using System.Security.Claims;
using Microsoft.IdentityModel.JsonWebTokens;

namespace SafeVault.Security;

public static class ClaimsPrincipalExtensions
{
    /// <summary>The authenticated user's id, taken only from the signed token, never from the request body.</summary>
    public static long GetUserId(this ClaimsPrincipal user) =>
        long.TryParse(user.FindFirstValue(JwtRegisteredClaimNames.Sub), out var id)
            ? id
            : throw new InvalidOperationException("Authenticated principal has no valid subject claim.");
}
