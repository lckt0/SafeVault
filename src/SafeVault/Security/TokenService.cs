using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using SafeVault.Models;

namespace SafeVault.Security;

public sealed class TokenService(IOptions<JwtOptions> options, TimeProvider clock)
{
    public const string RoleClaim = "role";
    public const string NameClaim = "name";

    private readonly JwtOptions _options = options.Value;
    private readonly JsonWebTokenHandler _handler = new();

    public static SymmetricSecurityKey CreateKey(string key) => new(Encoding.UTF8.GetBytes(key));

    public TokenResponse Issue(UserRecord user)
    {
        var now = clock.GetUtcNow().UtcDateTime;
        var expires = now.AddMinutes(_options.LifetimeMinutes);
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = _options.Issuer,
            Audience = _options.Audience,
            IssuedAt = now,
            NotBefore = now,
            Expires = expires,
            Subject = new ClaimsIdentity(
            [
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new Claim(NameClaim, user.Username),
                new Claim(RoleClaim, user.Role),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            ]),
            SigningCredentials = new SigningCredentials(CreateKey(_options.Key), SecurityAlgorithms.HmacSha256),
        };
        return new TokenResponse(_handler.CreateToken(descriptor), expires, user.Role);
    }
}
